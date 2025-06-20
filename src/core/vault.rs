// src/core/vault.rs
use crate::crypto;
use crate::core::auth::{AuthManager, Result as AuthResult, AuthError};
use crate::db::Database;
use crate::models::{PasswordEntry, PasswordFilter};
use uuid::Uuid;
use base64::Engine;
use std::sync::Arc;
use crate::importers::FirefoxImporter;
use sqlx::Acquire;
use crate::db::DbError;

pub struct Vault {
    db: Arc<Database>,
    pub auth_manager: AuthManager,
}

impl Vault {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            auth_manager: AuthManager::new(),
        }
    }

    pub async fn unlock(&self, master_password: &str) -> AuthResult<String> {
        self.auth_manager.authenticate(&self.db, master_password).await
    }

    pub async fn count_passwords(&self) -> Result<usize, DbError> {
        self.db.get_password_count().await
    }


    pub async fn add_password(
        &self,
        token: &str,
        site: &str,
        username: &str,
        password: &str,
        notes: Option<&str>,
        categories: &[String],
    ) -> AuthResult<Uuid> {
        let session_id = self.auth_manager.validate_token(token)?;
        let master_key = self.auth_manager.get_master_key(&session_id)?;
        let encrypted = crypto::encrypt_password(&master_key, password)?;
        let id = self.db.add_password(site, username, &encrypted, notes, categories).await?;
        Ok(id)
    }

    pub async fn get_all_passwords(&self, token: &str) -> AuthResult<Vec<PasswordEntry>> {
        // Validate token but we don't need the session_id for this operation
        let _session_id = self.auth_manager.validate_token(token)?;
        let passwords = self.db.get_all_passwords().await?;
        Ok(passwords)
    }

    pub async fn get_filtered_passwords(&self, token: &str, filter: &PasswordFilter) -> AuthResult<Vec<PasswordEntry>> {
        // Validate token but we don't need the session_id for this operation
        let _session_id = self.auth_manager.validate_token(token)?;
        let passwords = self.db.get_filtered_passwords(filter).await?;
        Ok(passwords)
    }

    pub async fn get_password_by_id(&self, token: &str, id: Uuid) -> AuthResult<PasswordEntry> {
        // Validate token but we don't need the session_id for this operation
        let _session_id = self.auth_manager.validate_token(token)?;
        let password = self.db.get_password_by_id(id).await?;
        Ok(password)
    }

    pub async fn update_password(
        &self,
        token: &str,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        password: Option<&str>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> AuthResult<()> {
        let session_id = self.auth_manager.validate_token(token)?;
        let master_key = self.auth_manager.get_master_key(&session_id)?;

        let encrypted_password = if let Some(pwd) = password {
            Some(crypto::encrypt_password(&master_key, pwd)?)
        } else {
            None
        };

        self.db.update_password(
            id,
            site,
            username,
            encrypted_password.as_deref(),
            notes,
            categories,
        ).await?;

        Ok(())
    }

    pub async fn delete_password(&self, token: &str, id: Uuid) -> AuthResult<()> {
        // Validate token but we don't need the session_id for this operation
        let _session_id = self.auth_manager.validate_token(token)?;
        self.db.delete_password(id).await?;
        Ok(())
    }

    pub async fn decrypt_password(&self, token: &str, encrypted: &[u8]) -> AuthResult<String> {
        let session_id = self.auth_manager.validate_token(token)?;
        let master_key = self.auth_manager.get_master_key(&session_id)?;
        let password = crypto::decrypt_password(&master_key, encrypted)?;
        Ok(password)
    }

    pub fn logout(&self, token: &str) -> AuthResult<()> {
        let session_id = self.auth_manager.validate_token(token)?;
        self.auth_manager.clear_session(&session_id)?;
        Ok(())
    }

    pub fn get_db_ref(&self) -> Arc<Database> {
        self.db.clone()
    }

    pub async fn verify_master_password(&self, password: &str) -> AuthResult<()> {
        let db = self.get_db_ref();
        let current_key = crypto::derive_key(password, &db).await?;
        let verification_key = "master_password_verification";
        let stored_hash = db.get_config_value(verification_key).await?;

        if let Some(hash_b64) = stored_hash {
            let hash_bytes = match base64::engine::general_purpose::STANDARD.decode(hash_b64) {
                Ok(bytes) => bytes,
                Err(_) => return Err(AuthError::InvalidFormat("Invalid hash format".into())),
            };

            match crypto::decrypt_password(&current_key, &hash_bytes) {
                Ok(verification_text) if verification_text == "VERIFIED" => Ok(()),
                _ => Err(AuthError::InvalidCredentials),
            }
        } else {
            Err(AuthError::InvalidFormat("No master password verification found".into()))
        }
    }

    pub async fn update_master_password(
        &self,
        token: &str,
        current_password: &str,
        new_password: &str
    ) -> AuthResult<()> {
        let session_id = self.auth_manager.validate_token(token)?;
        self.verify_master_password(current_password).await?;
        let db = self.get_db_ref();

        let current_key = crypto::derive_key(current_password, &db).await?;
        let new_key = crypto::derive_key(new_password, &db).await?;
        let passwords = db.get_all_passwords().await?;

        let mut tx = db.begin_transaction().await?;

        for password in passwords {
            let plain_password = crypto::decrypt_password(&current_key, &password.password)?;
            let new_encrypted = crypto::encrypt_password(&new_key, &plain_password)?;

            db.update_password_in_transaction(
                &mut tx,
                password.id,
                None,
                None,
                Some(&new_encrypted),
                None,
                None,
            ).await?;
        }

        let verification_data = "VERIFIED";
        let encrypted = crypto::encrypt_password(&new_key, verification_data)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        db.store_config_value_in_transaction(&mut tx, "master_password_verification", &encrypted_b64).await?;
        db.commit_transaction(tx).await?;
        self.auth_manager.update_session_key(&session_id, &new_key)?;

        Ok(())
    }

    pub async fn reset_master_password(&self, new_password: &str) -> AuthResult<()> {
        let db = self.get_db_ref();
        let new_key = crypto::derive_key(new_password, &db).await?;
        let passwords = db.get_all_passwords().await?;
        let mut tx = db.begin_transaction().await?;

        for password in passwords {
            let new_encrypted = crypto::encrypt_password(&new_key, "[RESET PASSWORD]")?;

            db.update_password_in_transaction(
                &mut tx,
                password.id,
                None,
                None,
                Some(&new_encrypted),
                None,
                None,
            ).await?;
        }

        let verification_data = "VERIFIED";
        let encrypted = crypto::encrypt_password(&new_key, verification_data)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        db.store_config_value_in_transaction(&mut tx, "master_password_verification", &encrypted_b64).await?;
        db.commit_transaction(tx).await?;

        Ok(())
    }

    pub fn get_backup_dir(&self) -> Result<std::path::PathBuf, crate::core::auth::AuthError> {
        let config_dir = match crate::utils::get_app_config_dir() {
            Some(dir) => dir,
            None => return Err(AuthError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Config directory not found",
            ))),
        };

        let backup_dir = config_dir.join("backups");

        if !backup_dir.exists() {
            std::fs::create_dir_all(&backup_dir).map_err(AuthError::IoError)?;
        }

        Ok(backup_dir)
    }
    
    pub async fn import_firefox_passwords(
        &self,
        token: &str,
        profile_path: Option<&str>,
        master_password: Option<&str>,
        category: Option<&str>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // Validate token and get the session_id
        let session_id = match self.auth_manager.validate_token(token) {
            Ok(sid) => sid,
            Err(_) => return Err("Invalid session token".into()),
        };
        
        // Get the master key from the session
        let master_key = match self.auth_manager.get_master_key(&session_id) {
            Ok(key) => key,
            Err(e) => return Err(format!("Failed to retrieve master key: {}", e).into()),
        };
        
        // Create importer
        let importer = FirefoxImporter::new();
        
        // Import using the master key, which is never exposed outside the Vault
        // Add update_existing parameter with default value of false
        let (added, updated) = importer.import_passwords(
            &self.db,
            profile_path,
            master_password,
            &master_key,  // Pass the master key to the importer
            category,
            false, // Default to not updating existing passwords
        ).await?;
        
        // Return total count (added + updated)
        Ok(added + updated)
    }
}