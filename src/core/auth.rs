// src/core/auth.rs
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;
// use base64::engine::general_purpose;
use base64::Engine;
use crate::db::Database;
use crate::crypto;
use crate::utils;

// For password verification
use argon2::{Argon2, PasswordHash, PasswordVerifier, PasswordHasher};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;

// Define JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    // Subject (user ID)
    pub sub: String,
    // Issued at
    pub iat: i64,
    // Expiration time
    pub exp: i64,
    // Session ID
    pub sid: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Invalid session")]
    InvalidSession,
    
    #[error("Crypto error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Argon2 error: {0}")]
    Argon2Error(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;

pub struct AuthManager {
    jwt_secret: String,
    session_dir: PathBuf,
    session_duration: Duration,
}

impl AuthManager {
    pub fn new() -> Self {
        // Create session directory if it doesn't exist
        let session_dir = utils::get_app_config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("sessions");
        
        if !session_dir.exists() {
            fs::create_dir_all(&session_dir).ok();
        }
        
        // Generate or load JWT secret
        let jwt_secret = Self::get_or_create_jwt_secret(&session_dir);
        
        Self {
            jwt_secret,
            session_dir,
            session_duration: Duration::hours(1), // Default session duration
        }
    }
    
    // Get or create JWT secret
    fn get_or_create_jwt_secret(session_dir: &PathBuf) -> String {
        let secret_file = session_dir.join("jwt_secret");
        
        if secret_file.exists() {
            match fs::read_to_string(&secret_file) {
                Ok(secret) => return secret,
                Err(_) => {}
            }
        }
        
        // Generate a new secret
        let secret = utils::generate_salt();
        fs::write(&secret_file, &secret).ok();
        
        secret
    }
    
    pub async fn authenticate(&self, db: &Database, master_password: &str) -> Result<String> {
        // Try to derive key from master password
        let master_key = crypto::derive_key(master_password, db).await?;
        
        // Check if there's a verification hash stored
        let verification_key = "master_password_verification";
        let stored_hash = db.get_config_value(verification_key).await?;
        
        if let Some(hash_b64) = stored_hash {
            // This is not the first login, we need to verify the password
            
            // Decode the stored hash
            let hash_bytes = match base64::engine::general_purpose::STANDARD.decode(hash_b64) {
                Ok(bytes) => bytes,
                Err(_) => return Err(AuthError::InvalidFormat("Invalid verification hash format".into())),
            };
            
            // Try to decrypt the verification data
            match crypto::decrypt_password(&master_key, &hash_bytes) {
                Ok(verification_text) => {
                    // The verification text should be "VERIFIED"
                    if verification_text != "VERIFIED" {
                        return Err(AuthError::InvalidCredentials);
                    }
                    println!("✅ Master password verified successfully");
                },
                Err(_) => {
                    // If decryption fails, the password is wrong
                    println!("❌ Invalid master password");
                    return Err(AuthError::InvalidCredentials);
                }
            }
        } else {
            // First-time login, set up verification
            println!("🔐 First-time setup: Creating master password verification");
            let verification_data = "VERIFIED";
            let encrypted = crypto::encrypt_password(&master_key, verification_data)?;
            let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
            
            // Store the verification hash
            db.store_config_value(verification_key, &encrypted_b64).await?;
            
            println!("✅ Master password set successfully");
        }
        
        // Create JWT token for the session
        let session_id = Uuid::new_v4().to_string();
        
        // Create claims
        let claims = Claims {
            sub: "user".to_string(),
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + self.session_duration).timestamp(),
            sid: session_id.clone(),
        };
        
        // Create JWT token
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;
        
        // Store session data securely
        self.save_session_data(&session_id, &master_key)?;
        
        Ok(token)
    }
    
    // Validate JWT token and return session ID
    pub fn validate_token(&self, token: &str) -> Result<String> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;
        
        let claims = token_data.claims;
        
        // Check if token is expired
        if claims.exp < Utc::now().timestamp() {
            return Err(AuthError::SessionExpired);
        }
        
        // Check if session file exists
        let session_file = self.session_dir.join(&claims.sid);
        if !session_file.exists() {
            return Err(AuthError::InvalidSession);
        }
        
        Ok(claims.sid)
    }
    
    // Get master key from session
    pub fn get_master_key(&self, session_id: &str) -> Result<Vec<u8>> {
        let session_file = self.session_dir.join(session_id);
        let encrypted_key = fs::read(&session_file)?;
        
        // In a real system, this would be encrypted with a separate key
        // For this demo, we'll just use the raw bytes
        Ok(encrypted_key)
    }
    
    // Save session data (master key)
    fn save_session_data(&self, session_id: &str, master_key: &[u8]) -> Result<()> {
        let session_file = self.session_dir.join(session_id);
        
        // In a real system, we would encrypt this data
        // For this demo, we'll just write the raw bytes
        fs::write(session_file, master_key)?;
        
        Ok(())
    }
    
    // Clear session
    pub fn clear_session(&self, session_id: &str) -> Result<()> {
        let session_file = self.session_dir.join(session_id);
        if session_file.exists() {
            fs::remove_file(session_file)?;
        }
        Ok(())
    }
    
    // Update the session key after changing master password
    pub fn update_session_key(&self, session_id: &str, new_master_key: &[u8]) -> Result<()> {
        // This method is called when changing the master password
        // It updates the stored session data with the new master key
        let session_file = self.session_dir.join(session_id);
        
        // In a real system, we would encrypt this data
        // For this demo, we'll just write the raw bytes
        fs::write(session_file, new_master_key)?;
        
        Ok(())
    }

    pub async fn store_web_password(&self, db: &Database, password: &str) -> Result<()> {
        // Generate a salt and hash the password with Argon2id
        let salt = SaltString::generate(&mut OsRng);
        
        // Configure Argon2id with standard parameters
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                65536, // 64 MB
                3,     // 3 iterations
                4,     // 4 parallel lanes
                None,
            ).unwrap(),
        );
        
        // Hash the password
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Argon2Error(e.to_string()))?;
        
        // Store the hash in the database
        db.store_config_value("web_interface_password", password_hash.to_string().as_str()).await?;
        
        Ok(())
    }
    
    // Verify a web interface password
    pub async fn verify_web_password(&self, db: &Database, password: &str) -> Result<bool> {
        // Get the stored hash
        let stored_hash = match db.get_config_value("web_interface_password").await? {
            Some(hash) => hash,
            None => return Ok(false), // No password set
        };
        
        // Parse the stored hash
        let parsed_hash = PasswordHash::new(&stored_hash)
            .map_err(|e| AuthError::InvalidFormat(format!("Invalid hash format: {}", e)))?;
        
        // Verify the password
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);
        
        Ok(result.is_ok())
    }
}