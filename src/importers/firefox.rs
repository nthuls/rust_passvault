// src/importers/firefox.rs
use std::path::PathBuf;
use crate::firefox::{FirefoxProfiler, FirefoxCredentialManager};
use crate::db::Database;
use crate::crypto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("Firefox profile error: {0}")]
    ProfileError(String),
    
    #[error("Credential extraction error: {0}")]
    CredentialError(String),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Encryption error: {0}")]
    CryptoError(#[from] crypto::CryptoError),
}

pub struct FirefoxImporter {
    profiler: FirefoxProfiler,
}

impl FirefoxImporter {
    pub fn new() -> Self {
        Self {
            profiler: FirefoxProfiler::new(),
        }
    }
    
    pub fn list_profiles(&self) -> Vec<(String, PathBuf)> {
        self.profiler.find_profiles()
    }
    
    pub async fn import_credentials(
        &self,
        profile_path: PathBuf,
        master_password: Option<&str>,
        db: &Database,
        vault_key: &[u8],
        category: Option<&str>,
    ) -> Result<usize, ImportError> {
        // Create credential manager
        let manager = FirefoxCredentialManager::new(profile_path);
        
        // Extract credentials
        let credentials = manager.extract_credentials(master_password)
            .map_err(|e| ImportError::CredentialError(e.to_string()))?;
        
        // Import into our database
        let mut count = 0;
        
        for cred in credentials {
            // Encrypt the password
            let encrypted = crypto::encrypt_password(vault_key, &cred.password)?;
            
            // Categories to apply
            let mut categories = Vec::new();
            if let Some(cat) = category {
                categories.push(cat.to_string());
            }
            categories.push("Firefox Import".to_string());
            
            // Add to database
            db.add_password(
                &cred.url,
                &cred.username,
                &encrypted,
                None,
                &categories,
            ).await?;
            
            count += 1;
        }
        
        Ok(count)
    }
    /// Import passwords from Firefox profiles
    pub async fn import_passwords(
        &self,
        db: &Database,
        profile_path: Option<&str>,
        master_password: Option<&str>,
        vault_key: &[u8],  // Added this parameter to accept master key
        category: Option<&str>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        // If a specific profile path is provided, use it
        if let Some(path_str) = profile_path {
            let path = std::path::PathBuf::from(path_str);
            return self.import_credentials(
                path,
                master_password,
                db,
                vault_key,  // Pass the vault key instead of an empty vector
                category,
            ).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
        }
        
        // Otherwise, try to find default profiles
        let profiles = self.list_profiles();
        if profiles.is_empty() {
            return Err("No Firefox profiles found".into());
        }
        
        // Use the first profile
        let (_, profile_path) = &profiles[0];
        self.import_credentials(
            profile_path.clone(),
            master_password,
            db,
            vault_key,  // Pass the vault key instead of an empty vector
            category,
        ).await.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
    
    /// Get available Firefox profiles
    pub fn get_available_profiles(&self) -> Result<Vec<(String, std::path::PathBuf)>, Box<dyn std::error::Error>> {
        let profiles = self.list_profiles();
        if profiles.is_empty() {
            return Err("No Firefox profiles found".into());
        }
        Ok(profiles)
    }
}