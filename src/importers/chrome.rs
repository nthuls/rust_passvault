// src/importers/chrome.rs

use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::env;
use std::process::Command;
use rusqlite::{Connection, Result as SqliteResult, Error as SqliteError, OpenFlags};
use crate::db::Database;
use crate::crypto;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use log::{info, warn, error, debug};

#[derive(Debug, Error)]
pub enum ChromeImportError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("SQLite error: {0}")]
    SqliteError(#[from] rusqlite::Error),
    
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] crate::crypto::CryptoError),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Operating system not supported")]
    UnsupportedOS,
}

// Credential structure from Chrome database
#[derive(Debug, Serialize, Deserialize)]
pub struct ChromeCredential {
    pub origin_url: String,
    pub username_value: String,
    pub password_value: Vec<u8>, // Encrypted password
}

pub struct ChromeImporter {
    os_type: String,
}

impl ChromeImporter {
    pub fn new() -> Self {
        let os_type = env::consts::OS.to_string();
        Self { os_type }
    }
    
    // Find Chrome profiles on the system
    pub fn list_profiles(&self) -> Vec<(String, PathBuf)> {
        let mut profiles = Vec::new();
        let default_path = self.get_default_profile_path();

        if let Some(dir) = default_path {
            if dir.exists() {
                let local_state_path = dir.join("Local State");
                if local_state_path.exists() {
                    if let Ok(content) = fs::read_to_string(local_state_path) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(profile_obj) = json.get("profile").and_then(|p| p.get("info_cache")) {
                                if let Some(profile_map) = profile_obj.as_object() {
                                    for (name, _) in profile_map {
                                        let profile_path = dir.join(name);
                                        if profile_path.exists() {
                                            profiles.push((name.clone(), profile_path));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if profiles.is_empty() {
                    let default_profile = dir.join("Default");
                    if default_profile.exists() {
                        profiles.push(("Default".to_string(), default_profile));
                    }
                }
            }
        }

        profiles
    }
    
    // Get default Chrome profile path based on OS
    fn get_default_profile_path(&self) -> Option<PathBuf> {
        match self.os_type.as_str() {
            "windows" => {
                if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
                    Some(PathBuf::from(local_app_data).join("Google\\Chrome\\User Data"))
                } else {
                    None
                }
            },
            "macos" => {
                if let Some(home) = env::var_os("HOME") {
                    Some(PathBuf::from(home).join("Library/Application Support/Google/Chrome"))
                } else {
                    None
                }
            },
            "linux" => {
                if let Some(home) = env::var_os("HOME") {
                    Some(PathBuf::from(home).join(".config/google-chrome"))
                } else {
                    None
                }
            },
            _ => None,
        }
    }
    
    // Extract credentials from a Chrome profile
    pub fn extract_credentials(&self, profile_path: PathBuf) -> Result<Vec<ChromeCredential>, ChromeImportError> {
        let login_data_path = profile_path.join("Login Data");
        
        if !login_data_path.exists() {
            return Err(ChromeImportError::ProfileNotFound(format!(
                "Login Data not found at: {}", login_data_path.display()
            )));
        }
        
        // Create a temporary copy of the database file because Chrome might have it locked
        let temp_dir = tempfile::tempdir()?;
        let temp_db_path = temp_dir.path().join("temp_chrome_login_data.db");
        fs::copy(&login_data_path, &temp_db_path)?;
        
        // Open the SQLite database
        let conn = Connection::open_with_flags(
            &temp_db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        
        // Query for saved credentials
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value FROM logins"
        )?;
        
        let credential_iter = stmt.query_map([], |row| {
            Ok(ChromeCredential {
                origin_url: row.get(0)?,
                username_value: row.get(1)?,
                password_value: row.get(2)?,
            })
        })?;
        
        let mut credentials = Vec::new();
        for credential in credential_iter {
            if let Ok(cred) = credential {
                credentials.push(cred);
            }
        }
        
        Ok(credentials)
    }
    
    // Decrypt Chrome passwords (different methods depending on OS)
    pub fn decrypt_credentials(&self, credentials: Vec<ChromeCredential>) -> Vec<(String, String, String)> {
        let mut decrypted = Vec::new();
        
        for cred in credentials {
            let decrypted_password = match self.os_type.as_str() {
                "windows" => self.decrypt_password_windows(&cred.password_value),
                "macos" => self.decrypt_password_macos(&cred.password_value),
                "linux" => self.decrypt_password_linux(&cred.password_value),
                _ => Err(ChromeImportError::UnsupportedOS),
            };
            
            match decrypted_password {
                Ok(password) => {
                    decrypted.push((
                        cred.origin_url,
                        cred.username_value,
                        password,
                    ));
                },
                Err(e) => {
                    error!("Failed to decrypt password: {}", e);
                    // Skip this credential
                }
            }
        }
        
        decrypted
    }
    
    // Windows-specific decryption
    fn decrypt_password_windows(&self, encrypted: &[u8]) -> Result<String, ChromeImportError> {
        // Chrome on Windows uses Windows Data Protection API (DPAPI)
        // The first 5 bytes are "DPAPI" prefix (v10) or 3 bytes (v1-v9)
        if encrypted.len() < 5 {
            return Err(ChromeImportError::DecryptionError("Encrypted data too short".to_string()));
        }
        
        let dpapi_prefix = b"DPAPI";
        let (encrypted_data, is_v10) = if &encrypted[0..5] == dpapi_prefix {
            (&encrypted[5..], true)
        } else {
            (&encrypted[3..], false)
        };
        
        // Use dpapi crate to decrypt
        // This requires the Windows API
        #[cfg(target_os = "windows")]
        {
            use winapi::um::dpapi::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
            use winapi::um::wincrypt::DATA_BLOB;
            use std::ptr::null_mut;
            
            let mut in_blob = DATA_BLOB {
                cbData: encrypted_data.len() as u32,
                pbData: encrypted_data.as_ptr() as *mut u8,
            };
            
            let mut out_blob = DATA_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };
            
            let result = unsafe {
                CryptUnprotectData(
                    &mut in_blob,
                    null_mut(),  // ppszDataDescr
                    null_mut(),  // pOptionalEntropy
                    null_mut(),  // pvReserved
                    null_mut(),  // pPromptStruct
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out_blob,
                )
            };
            
            if result == 0 {
                return Err(ChromeImportError::DecryptionError(
                    "DPAPI decryption failed".to_string()
                ));
            }
            
            let decrypted_bytes = unsafe {
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize)
            };
            
            // Convert bytes to string
            let password = String::from_utf8_lossy(decrypted_bytes).to_string();
            
            // Free the memory allocated by CryptUnprotectData
            unsafe {
                winapi::um::wincrypt::LocalFree(out_blob.pbData as _);
            }
            
            Ok(password)
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            Err(ChromeImportError::UnsupportedOS)
        }
    }
    
    // macOS-specific decryption
    fn decrypt_password_macos(&self, encrypted: &[u8]) -> Result<String, ChromeImportError> {
        // Chrome on macOS uses the system keychain
        // We'll use the 'security' command-line tool
        
        // Create a temporary file with the encrypted data
        let temp_dir = tempfile::tempdir()?;
        let temp_file_path = temp_dir.path().join("chrome_password.bin");
        fs::write(&temp_file_path, encrypted)?;
        
        // Run the security command to decrypt
        let output = Command::new("security")
            .args(&[
                "find-generic-password",
                "-a", "Chrome",
                "-s", "Chrome Safe Storage",
                "-w",
            ])
            .output()?;
        
        if !output.status.success() {
            return Err(ChromeImportError::DecryptionError(
                "Failed to retrieve Chrome Safe Storage password".to_string()
            ));
        }
        
        let key = output.stdout;
        
        // Chrome uses AES-128-CBC for encryption on macOS
        // This would require additional crypto code to implement
        // For now, return a placeholder error
        Err(ChromeImportError::DecryptionError(
            "macOS decryption not fully implemented".to_string()
        ))
    }
    
    // Linux-specific decryption
    fn decrypt_password_linux(&self, encrypted: &[u8]) -> Result<String, ChromeImportError> {
        // Check if password is stored without encryption
        if let Ok(password) = String::from_utf8(encrypted.to_vec()) {
            if !password.is_empty() {
                return Ok(password);
            }
        }
        
        // On Linux, Chrome sometimes uses a hardcoded key ("peanuts")
        // or the GNOME keyring
        
        // Try the hardcoded key first
        let key = b"peanuts";
        
        // Chrome uses AES-128-CBC for encryption on Linux
        // This would require additional crypto code to implement
        // For now, return a placeholder error
        Err(ChromeImportError::DecryptionError(
            "Linux decryption not fully implemented".to_string()
        ))
    }
    
    // Import passwords from Chrome to our database
    // Updated to support checking for existing passwords and optionally updating them
    pub async fn import_passwords(
        &self,
        db: &Database,
        profile_path: Option<&str>,
        vault_key: &[u8],
        category: Option<&str>,
        update_existing: Option<bool>, // New parameter to control updating behavior
    ) -> Result<(usize, usize), ChromeImportError> { // Updated return type to provide (added, updated) counts
        // Default to not updating if not specified
        let update_existing = update_existing.unwrap_or(false);
        
        // Determine which profile to use
        let profile = if let Some(path) = profile_path {
            PathBuf::from(path)
        } else {
            // Use default profile
            let profiles = self.list_profiles();
            if profiles.is_empty() {
                return Err(ChromeImportError::ProfileNotFound(
                    "No Chrome profiles found".to_string()
                ));
            }
            profiles[0].1.clone()
        };
        
        // Extract credentials
        let credentials = self.extract_credentials(profile)?;
        
        // Decrypt the credentials
        let decrypted = self.decrypt_credentials(credentials);
        
        // Import to database
        let mut added_count = 0;
        let mut updated_count = 0;
        
        // Set up categories
        let mut categories = Vec::new();
        if let Some(cat) = category {
            categories.push(cat.to_string());
        }
        categories.push("Chrome Import".to_string());
        
        // Add or update each password in the database
        for (site, username, password) in decrypted {
            // Encrypt the password with our vault key
            let encrypted = crypto::encrypt_password(vault_key, &password)?;
            
            // Add or update in database using the new method
            match db.add_or_update_password(
                &site,
                &username,
                &encrypted,
                None,
                &categories,
                update_existing,
            ).await {
                Ok((_, true)) => updated_count += 1, // Password was updated
                Ok((_, false)) => added_count += 1,  // Password was added or skipped (because it exists and update_existing is false)
                Err(e) => return Err(ChromeImportError::DbError(e)),
            }
        }
        
        Ok((added_count, updated_count))
    }
}