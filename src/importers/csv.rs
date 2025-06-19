// src/importers/csv.rs
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, BufRead, Write};
use crate::db::Database;
use crate::crypto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CsvImportError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("CSV format error at line {0}: {1}")]
    FormatError(usize, String),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Encryption error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
}

pub struct CsvImporter;

impl CsvImporter {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn import(
        &self,
        path: &Path,
        db: &Database,
        vault_key: &[u8],
        delimiter: char,
        has_header: bool,
        category: Option<&str>,
    ) -> Result<usize, CsvImportError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut count = 0;
        
        for (line_num, line_result) in reader.lines().enumerate() {
            // Skip header line if present
            if has_header && line_num == 0 {
                continue;
            }
            
            let line = line_result?;
            let parts: Vec<&str> = line.split(delimiter).collect();
            
            if parts.len() < 3 {
                return Err(CsvImportError::FormatError(
                    line_num + 1,
                    "Each line must have at least site, username, and password columns".to_string(),
                ));
            }
            
            let site = parts[0].trim();
            let username = parts[1].trim();
            let password = parts[2].trim();
            
            // Get optional notes if present
            let notes = if parts.len() > 3 {
                Some(parts[3].trim())
            } else {
                None
            };
            
            // Encrypt the password
            let encrypted = crypto::encrypt_password(vault_key, password)?;
            
            // Categories to apply
            let mut categories = Vec::new();
            if let Some(cat) = category {
                categories.push(cat.to_string());
            }
            categories.push("CSV Import".to_string());
            
            // Add to database
            db.add_password(
                site,
                username,
                &encrypted,
                notes,
                &categories,
            ).await?;
            
            count += 1;
        }
        
        Ok(count)
    }
    
    // Export passwords to CSV
    pub async fn export(
        &self,
        path: &Path,
        db: &Database,
        vault_key: &[u8],
        delimiter: char,
        include_header: bool,
    ) -> Result<usize, CsvImportError> {
        // Get all passwords
        let passwords = db.get_all_passwords().await
            .map_err(|e| CsvImportError::DbError(e))?;
        
        // Open file for writing
        let mut file = std::fs::File::create(path)?;
        
        // Write header if requested
        if include_header {
            writeln!(file, "site{}username{}password{}notes{}categories", 
                delimiter, delimiter, delimiter, delimiter)?;
        }
        
        // Write each password
        for entry in &passwords {
            // Decrypt the password
            let password = crypto::decrypt_password(vault_key, &entry.password)
                .map_err(|e| CsvImportError::CryptoError(e))?;
            
            // Format categories as comma-separated string
            let categories = entry.categories.join(",");
            
            // Write the line
            writeln!(
                file,
                "{}{}{}{}{}{}{}{}{}",
                entry.site, delimiter,
                entry.username, delimiter,
                password, delimiter,
                entry.notes.as_deref().unwrap_or(""), delimiter,
                categories
            )?;
        }
        
        Ok(passwords.len())
    }
}