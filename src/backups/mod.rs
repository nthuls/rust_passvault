// src/backup/mod.rs
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use chrono::{Utc, DateTime};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::db::Database;
use crate::crypto;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BackupError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Encryption error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Backup not found: {0}")]
    NotFound(String),
    
    #[error("Invalid backup file: {0}")]
    InvalidBackup(String),
    
    #[error("Invalid backup password")]
    InvalidPassword,
}

pub type Result<T> = std::result::Result<T, BackupError>;

#[derive(Serialize, Deserialize)]
struct BackupHeader {
    version: String,
    created_at: DateTime<Utc>,
    description: Option<String>,
    password_count: usize,
    category_count: usize,
    requires_password: bool,
    checksum: String,  // SHA-256 of the encrypted data
}

#[derive(Serialize, Deserialize)]
struct BackupMetadataFile {
    backups: Vec<BackupMetadata>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BackupMetadata {
    pub id: String,
    pub filename: String,
    pub created_at: String,
    pub description: Option<String>,
    pub size_bytes: u64,
    pub password_count: usize,
    pub category_count: usize,
}

pub struct BackupManager {
    backup_dir: PathBuf,
}

impl BackupManager {
    pub fn new(backup_dir: PathBuf) -> Self {
        if !backup_dir.exists() {
            fs::create_dir_all(&backup_dir).ok();
        }
        
        Self { backup_dir }
    }
    
    fn get_backup_dir(&self) -> std::io::Result<PathBuf> {
        if !self.backup_dir.exists() {
            fs::create_dir_all(&self.backup_dir)?;
        }
        Ok(self.backup_dir.clone())
    }

    pub fn get_all_backups(&self) -> std::io::Result<Vec<BackupMetadata>> {
        let backup_dir = self.get_backup_dir()?;
        let mut backups = Vec::new();

        for entry in fs::read_dir(backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "vault") {
                if let Ok(metadata) = self.get_backup_details(
                    &path.file_stem().unwrap_or_default().to_string_lossy()
                ) {
                    backups.push(metadata);
                }
            }
        }

        Ok(backups)
    }

    /// List all backups
    pub fn list_backups(&self) -> Result<Vec<BackupMetadata>> {
        let metadata_file = self.backup_dir.join("metadata.json");
        
        if !metadata_file.exists() {
            return Ok(Vec::new());
        }
        
        let file_content = fs::read_to_string(metadata_file)?;
        let metadata: BackupMetadataFile = serde_json::from_str(&file_content)?;
        
        Ok(metadata.backups)
    }
    
    /// Get details for a specific backup
    pub fn get_backup_details(&self, id: &str) -> Result<BackupMetadata> {
        let backups = self.list_backups()?;
        
        backups.iter()
            .find(|b| b.id == id)
            .cloned()
            .ok_or_else(|| BackupError::NotFound(id.to_string()))
    }
    
    /// Create a new backup
    pub async fn create_backup(
        &self,
        db: &Database,
        master_key: &[u8],
        description: Option<String>,
        backup_password: Option<&str>,
    ) -> Result<BackupMetadata> {
        // Generate a unique filename based on the current time
        let now = Utc::now();
        let filename = format!("{}.vault", now.format("%Y-%m-%d-%H%M%S"));
        let backup_path = self.backup_dir.join(&filename);
        
        // Get password and category counts
        let passwords = db.get_all_passwords().await?;
        let categories = db.get_all_categories().await?;
        
        // Determine encryption key
        let encryption_key = if let Some(password) = backup_password {
            // Derive a key from the backup password
            crypto::derive_key(password, db).await?
        } else {
            // Use the master key
            master_key.to_vec()
        };
        
        // Create a JSON dump of the database
        // This is a simplified approach - you might want to add more data
        let db_dump = serde_json::to_string(&passwords)?;
        
        // Encrypt the database dump
        let encrypted_data = crypto::encrypt_password(&encryption_key, &db_dump)?;
        
        // Calculate checksum of the encrypted data
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_data);
        let checksum = format!("{:x}", hasher.finalize());
        
        // Create backup header
        let header = BackupHeader {
            version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: now,
            description: description.clone(),
            password_count: passwords.len(),
            category_count: categories.len(),
            requires_password: backup_password.is_some(),
            checksum,
        };
        
        // Serialize and write header
        let header_json = serde_json::to_string(&header)?;
        
        // Write the backup file
        let mut file = File::create(&backup_path)?;
        
        // Format: [header length (4 bytes)][header json][encrypted data]
        let header_len = header_json.len() as u32;
        file.write_all(&header_len.to_be_bytes())?;
        file.write_all(header_json.as_bytes())?;
        file.write_all(&encrypted_data)?;
        
        // Get file size
        let size_bytes = file.metadata()?.len();
        
        // Create backup metadata
        let backup_id = Uuid::new_v4().to_string();
        let backup_metadata = BackupMetadata {
            id: backup_id,
            filename,
            created_at: now.to_rfc3339(),
            description,
            size_bytes,
            password_count: passwords.len(),
            category_count: categories.len(),
        };
        
        // Update metadata file
        self.update_metadata(backup_metadata.clone())?;
        
        Ok(backup_metadata)
    }
    
    /// Restore from a backup
    pub async fn restore_backup(
        &self,
        id: &str,
        db: &Database,
        master_key: &[u8],
        backup_password: Option<&str>,
    ) -> Result<()> {
        // Get backup details
        let backup = self.get_backup_details(id)?;
        let backup_path = self.backup_dir.join(&backup.filename);
        
        if !backup_path.exists() {
            return Err(BackupError::NotFound(format!("Backup file not found: {}", backup.filename)));
        }
        
        // Read the backup file
        let mut file = File::open(backup_path)?;
        
        // Read header length
        let mut header_len_bytes = [0u8; 4];
        file.read_exact(&mut header_len_bytes)?;
        let header_len = u32::from_be_bytes(header_len_bytes) as usize;
        
        // Read header
        let mut header_bytes = vec![0u8; header_len];
        file.read_exact(&mut header_bytes)?;
        let header_str = String::from_utf8(header_bytes)
            .map_err(|_| BackupError::InvalidBackup("Invalid header encoding".to_string()))?;
        
        let header: BackupHeader = serde_json::from_str(&header_str)
            .map_err(|_| BackupError::InvalidBackup("Invalid header format".to_string()))?;
        
        // Read encrypted data
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;
        
        // Verify checksum
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_data);
        let checksum = format!("{:x}", hasher.finalize());
        
        if checksum != header.checksum {
            return Err(BackupError::InvalidBackup("Checksum verification failed".to_string()));
        }
        
        // Determine decryption key
        let decryption_key = if header.requires_password {
            if let Some(password) = backup_password {
                // Derive a key from the backup password
                crypto::derive_key(password, db).await?
            } else {
                return Err(BackupError::InvalidPassword);
            }
        } else {
            // Use the master key
            master_key.to_vec()
        };
        
        // Decrypt the data
        let decrypted_data = crypto::decrypt_password(&decryption_key, &encrypted_data)
            .map_err(|_| BackupError::InvalidPassword)?;
        
        // Parse the decrypted data
        let passwords: Vec<crate::models::PasswordEntry> = serde_json::from_str(&decrypted_data)
            .map_err(|_| BackupError::InvalidBackup("Invalid backup data format".to_string()))?;
        
        // Begin database transaction
        let mut tx = db.begin_transaction().await?;
        
        // Clear existing data (optional, depending on your requirements)
        // You might want to add confirmation for this step
        
        // Insert all passwords from backup
        for password in passwords {
            // You'll need to implement a method to restore passwords in a transaction
            db.restore_password_in_transaction(&mut tx, password).await?;
        }
        
        // Commit transaction
        db.commit_transaction(tx).await?;
        
        Ok(())
    }
    
    /// Delete a backup
    pub fn delete_backup(&self, id: &str) -> Result<()> {
        // Get backup details
        let backup = self.get_backup_details(id)?;
        let backup_path = self.backup_dir.join(&backup.filename);
        
        // Delete the backup file if it exists
        if backup_path.exists() {
            fs::remove_file(backup_path)?;
        }
        
        // Update metadata file
        let mut backups = self.list_backups()?;
        backups.retain(|b| b.id != id);
        
        let metadata_file = BackupMetadataFile { backups };
        let json = serde_json::to_string_pretty(&metadata_file)?;
        
        fs::write(self.backup_dir.join("metadata.json"), json)?;
        
        Ok(())
    }
    
    // Helper method to update metadata file with a new backup
    fn update_metadata(&self, new_backup: BackupMetadata) -> Result<()> {
        let metadata_path = self.backup_dir.join("metadata.json");
        
        let mut backups = if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            let metadata: BackupMetadataFile = serde_json::from_str(&content)
                .unwrap_or_else(|_| BackupMetadataFile { backups: Vec::new() });
            metadata.backups
        } else {
            Vec::new()
        };
        
        // Add the new backup
        backups.push(new_backup);
        
        // Sort by creation date (newest first)
        backups.sort_by(|a, b| {
            b.created_at.cmp(&a.created_at)
        });
        
        // Write updated metadata
        let metadata_file = BackupMetadataFile { backups };
        let json = serde_json::to_string_pretty(&metadata_file)?;
        
        fs::write(metadata_path, json)?;
        
        Ok(())
    }
}