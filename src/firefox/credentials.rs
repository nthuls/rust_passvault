// src/firefox/credentials.rs
use std::path::{Path, PathBuf};
use std::fs;
use rusqlite::Connection;
use serde_json::Value;
use thiserror::Error;

use crate::models::FirefoxCredential;
use super::nss::NSSDecryptor;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    
    #[error("NSS error: {0}")]
    NssError(String),
    
    #[error("No credentials found")]
    NoCredentials,
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

pub type Result<T> = std::result::Result<T, CredentialError>;

// Types of credential stores
pub enum CredentialStore {
    Json(PathBuf),
    Sqlite(PathBuf),
}

// Firefox credential manager
pub struct FirefoxCredentialManager {
    profile_path: PathBuf,
    store: Option<CredentialStore>,
}

impl FirefoxCredentialManager {
    // Create a new credential manager for a profile
    pub fn new(profile_path: PathBuf) -> Self {
        let mut manager = Self {
            profile_path: profile_path.clone(),
            store: None,
        };
        
        // Determine credential store
        let logins_json = profile_path.join("logins.json");
        if logins_json.exists() {
            manager.store = Some(CredentialStore::Json(logins_json));
        } else {
            let signons_sqlite = profile_path.join("signons.sqlite");
            if signons_sqlite.exists() {
                manager.store = Some(CredentialStore::Sqlite(signons_sqlite));
            }
        }
        
        manager
    }
    
    // Extract credentials from the profile
    pub fn extract_credentials(&self, master_password: Option<&str>) -> Result<Vec<FirefoxCredential>> {
        let store = self.store.as_ref().ok_or(CredentialError::NoCredentials)?;
        
        // Initialize NSS library for decryption
        let mut decryptor = NSSDecryptor::new();
        decryptor.initialize(&self.profile_path, master_password)
            .map_err(|e| CredentialError::NssError(e))?;
        
        // Extract based on store type
        let credentials = match store {
            CredentialStore::Json(path) => self.extract_from_json(path, &decryptor)?,
            CredentialStore::Sqlite(path) => self.extract_from_sqlite(path, &decryptor)?,
        };
        
        // Shutdown NSS
        decryptor.shutdown().map_err(|e| CredentialError::NssError(e))?;
        
        Ok(credentials)
    }
    
    // Extract from JSON store (newer Firefox)
    fn extract_from_json(&self, path: &Path, decryptor: &NSSDecryptor) -> Result<Vec<FirefoxCredential>> {
        let json_content = fs::read_to_string(path)?;
        let json: Value = serde_json::from_str(&json_content)?;
        
        let mut credentials = Vec::new();
        
        if let Some(logins) = json.get("logins").and_then(|v| v.as_array()) {
            for login in logins {
                if let (
                    Some(hostname),
                    Some(enc_username),
                    Some(enc_password),
                    Some(time_created),
                ) = (
                    login.get("hostname").and_then(|v| v.as_str()),
                    login.get("encryptedUsername").and_then(|v| v.as_str()),
                    login.get("encryptedPassword").and_then(|v| v.as_str()),
                    login.get("timeCreated").and_then(|v| v.as_u64()),
                ) {
                    // Decrypt username and password
                    let username = match decryptor.decrypt(enc_username) {
                        Ok(u) => u,
                        Err(e) => return Err(CredentialError::DecryptionError(e)),
                    };
                    
                    let password = match decryptor.decrypt(enc_password) {
                        Ok(p) => p,
                        Err(e) => return Err(CredentialError::DecryptionError(e)),
                    };
                    
                    // Convert timeCreated (milliseconds since epoch) to DateTime
                    let created_at = chrono::DateTime::from_timestamp(
                        (time_created / 1000) as i64,
                        ((time_created % 1000) * 1_000_000) as u32,
                    );
                    
                    credentials.push(FirefoxCredential {
                        url: hostname.to_string(),
                        username,
                        password,
                        created_at,
                    });
                }
            }
        }
        
        Ok(credentials)
    }
    
    // Extract from SQLite store (older Firefox)
    fn extract_from_sqlite(&self, path: &Path, decryptor: &NSSDecryptor) -> Result<Vec<FirefoxCredential>> {
        let conn = Connection::open(path)?;
        
        let mut stmt = conn.prepare(
            "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins",
        )?;
        
        let mut credentials = Vec::new();
        
        let rows = stmt.query_map([], |row| {
            let hostname: String = row.get(0)?;
            let enc_username: String = row.get(1)?;
            let enc_password: String = row.get(2)?;
            
            Ok((hostname, enc_username, enc_password))
        })?;
        
        for row_result in rows {
            let (hostname, enc_username, enc_password) = row_result?;
            
            // Decrypt username and password
            let username = match decryptor.decrypt(&enc_username) {
                Ok(u) => u,
                Err(e) => return Err(CredentialError::DecryptionError(e)),
            };
            
            let password = match decryptor.decrypt(&enc_password) {
                Ok(p) => p,
                Err(e) => return Err(CredentialError::DecryptionError(e)),
            };
            
            credentials.push(FirefoxCredential {
                url: hostname,
                username,
                password,
                created_at: None, // SQLite store doesn't have creation time
            });
        }
        
        Ok(credentials)
    }
}