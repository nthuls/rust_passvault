// src/crypto.rs
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use rand::{Rng, distributions::Uniform, seq::SliceRandom, RngCore};
use thiserror::Error;
use crate::db::DbError;
use crate::models::PasswordGenerationOptions;
use rand::distributions::Distribution;
use crate::db::Database;
use chacha20poly1305::{ChaCha20Poly1305};
use base64::Engine;

impl From<DbError> for CryptoError {
    fn from(e: DbError) -> Self {
        CryptoError::InvalidFormat(format!("DB Error: {}", e))
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Argon2 error: {0}")]
    Argon2Error(String),  // Manual conversion from argon2 error

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid data format: {0}")]
    InvalidFormat(String),

    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[error("Database error: {0}")]
    DbError(#[from] sqlx::Error),
    
    #[error("Key size error: {0}")]
    KeySizeError(String),
    
    #[error("Hashing error: {0}")]
    HashingError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

// Derive a key from the master password
pub async fn derive_key(master_password: &str, db: &Database) -> Result<Vec<u8>> {
    // Use default Argon2 parameters
    let kdf_memory_cost = 65536;  // 64 MB
    let kdf_time_cost = 3;
    let kdf_parallelism = 4;

    // Get or create a salt
    let salt_b64 = match db.get_config_value("vault_salt").await? {
        Some(salt) => salt,
        None => {
            // Generate a new salt
            let salt = SaltString::generate(&mut OsRng);
            let salt_b64 = salt.as_str().to_string();
            
            // Store it in the database
            db.store_config_value("vault_salt", &salt_b64).await?;
            
            salt_b64
        }
    };
    
    // Parse the stored salt
    let salt = SaltString::from_b64(&salt_b64)
        .map_err(|_| CryptoError::InvalidFormat("Invalid salt format".into()))?;
    
    // Configure Argon2id with standard parameters
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            kdf_memory_cost,
            kdf_time_cost,
            kdf_parallelism,
            None,
        ).unwrap(),
    );
    
    // Hash the password to derive encryption key
    let password_hash = argon2
    .hash_password(master_password.as_bytes(), &salt)
    .map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
    
    // Extract bytes for encryption key
    Ok(password_hash.hash.unwrap().as_bytes().to_vec())
}

// Encrypt a password with AES-GCM
pub fn encrypt_password(key: &[u8], plaintext: &str) -> Result<Vec<u8>> {
    // Create a proper key for AES-GCM
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    
    // Create the cipher
    let cipher = Aes256Gcm::new(aes_key);
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let nonce_bytes = nonce.to_vec();
    
    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    
    // Combine nonce and ciphertext for storage
    let mut encrypted = nonce_bytes;
    encrypted.extend_from_slice(&ciphertext);
    
    Ok(encrypted)
}

// Decrypt a password with AES-GCM
pub fn decrypt_password(key: &[u8], ciphertext: &[u8]) -> Result<String> {
    // Ensure the ciphertext is long enough to contain a nonce
    if ciphertext.len() <= 12 {
        return Err(CryptoError::InvalidFormat("Ciphertext too short".into()));
    }
    
    // Split the ciphertext into nonce and encrypted data
    let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
    
    // Create the AES key
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    
    // Create the cipher
    let cipher = Aes256Gcm::new(aes_key);
    
    // Create a nonce from the stored bytes
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the data
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    // Convert back to UTF-8 string
    let password = String::from_utf8(plaintext)?;
    
    Ok(password)
}

// Verify a master password against a stored verification hash
pub fn verify_master_password(derived_key: &[u8], encrypted_verification: &[u8]) -> bool {
    match decrypt_password(derived_key, encrypted_verification) {
        Ok(decrypted) => decrypted == "VERIFIED",
        Err(_) => false
    }
}

// Generate a strong password
pub fn generate_password(options: &PasswordGenerationOptions) -> String {
    let mut rng = rand::thread_rng();
    
    // Define character sets based on options
    let mut chars = Vec::new();
    
    if options.include_lowercase {
        chars.extend(b"abcdefghijklmnopqrstuvwxyz");
    }
    if options.include_uppercase {
        chars.extend(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if options.include_numbers {
        chars.extend(b"0123456789");
    }
    if options.include_symbols {
        chars.extend(b"!@#$%^&*()-_=+[]{}|;:,.<>?");
    }
    
    // Ensure we have at least some characters
    if chars.is_empty() {
        // Default to lowercase if nothing selected
        chars.extend(b"abcdefghijklmnopqrstuvwxyz");
    }
    
    // Remove similar characters if requested
    if options.exclude_similar {
        let similar = b"il1Lo0O";
        chars.retain(|c| !similar.contains(c));
    }
    
    if options.memorable {
        // Generate a more memorable password with dictionary words
        // This is a more advanced implementation with common words
        let words = [
            // Common nouns
            "apple", "banana", "orange", "grape", "melon", "house", "garden", 
            "beach", "mountain", "river", "coffee", "pizza", "burger", "pasta", 
            "salad", "cloud", "tiger", "eagle", "horse", "dragon", "castle", 
            "guitar", "piano", "ocean", "planet", "rocket", "camera", "pencil",
            
            // Common adjectives
            "happy", "sunny", "cloudy", "windy", "rainy", "bright", "dark",
            "fast", "slow", "cold", "hot", "tall", "short", "round", "square",
            "loud", "quiet", "fresh", "sweet", "sour", "clean", "dirty", "soft",
            "hard", "smooth", "rough", "light", "heavy", "early", "late", "new",
            "old", "young", "rich", "poor", "busy", "calm", "brave", "wise",
        ];
        
        let mut password = String::new();
        
        // Choose 2-3 random words based on desired length
        let num_words = if options.length < 12 { 2 } else { 3 };
        
        for i in 0..num_words {
            // Select a random word
            let mut word = words.choose(&mut rng).unwrap().to_string();
            
            // Capitalize if uppercase is enabled
            if options.include_uppercase && rng.gen_bool(0.5) {
                let first_char = word.remove(0).to_uppercase().next().unwrap();
                word = format!("{}{}", first_char, word);
            }
            
            password.push_str(&word);
            
            // Add a separator between words, except for the last word
            if i < num_words - 1 {
                if options.include_numbers && options.include_symbols {
                    // Use either a number or a symbol
                    if rng.gen_bool(0.5) {
                        password.push(rng.gen_range(b'0'..=b'9') as char);
                    } else {
                        password.push("!@#$%^&*".chars().nth(rng.gen_range(0..8)).unwrap());
                    }
                } else if options.include_numbers {
                    password.push(rng.gen_range(b'0'..=b'9') as char);
                } else if options.include_symbols {
                    password.push("!@#$%^&*".chars().nth(rng.gen_range(0..8)).unwrap());
                } else {
                    // Default separator if no numbers or symbols
                    password.push('-');
                }
            }
        }
        
        // If password is shorter than requested length, add some random characters
        if password.len() < options.length {
            let dist = Uniform::from(0..chars.len());
            while password.len() < options.length {
                password.push(chars[dist.sample(&mut rng)] as char);
            }
        }
        
        // If password is longer than requested length, truncate
        if password.len() > options.length {
            password.truncate(options.length);
        }
        
        password
    } else {
        // Generate a fully random password
        let dist = Uniform::from(0..chars.len());
        
        // Ensure password meets complexity requirements if specified
        let mut password: String = (0..options.length)
            .map(|_| chars[dist.sample(&mut rng)] as char)
            .collect();
        
        // Check and enforce complexity if needed
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_number = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());
        
        // If we're missing any required character type, replace a random
        // character with one of the required type
        if options.include_lowercase && !has_lowercase && !password.is_empty() {
            let pos = rng.gen_range(0..password.len());
            let lowercase = b"abcdefghijklmnopqrstuvwxyz";
            let new_char = lowercase[rng.gen_range(0..lowercase.len())] as char;
            password.replace_range(pos..pos+1, &new_char.to_string());
        }
        
        if options.include_uppercase && !has_uppercase && password.len() > 1 {
            let pos = rng.gen_range(0..password.len());
            let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let new_char = uppercase[rng.gen_range(0..uppercase.len())] as char;
            password.replace_range(pos..pos+1, &new_char.to_string());
        }
        
        if options.include_numbers && !has_number && password.len() > 2 {
            let pos = rng.gen_range(0..password.len());
            let new_char = rng.gen_range(b'0'..=b'9') as char;
            password.replace_range(pos..pos+1, &new_char.to_string());
        }
        
        if options.include_symbols && !has_symbol && password.len() > 3 {
            let pos = rng.gen_range(0..password.len());
            let symbols = b"!@#$%^&*()-_=+[]{}|;:,.<>?";
            let new_char = symbols[rng.gen_range(0..symbols.len())] as char;
            password.replace_range(pos..pos+1, &new_char.to_string());
        }
        
        password
    }
}

// Analyze password strength
pub fn analyze_password_strength(password: &str) -> u8 {
    let mut score = 0;
    
    // Length contribution (up to 40 points)
    score += (password.len() as u8).min(40);
    
    // Character variety (up to 20 points each)
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        score += 10;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        score += 10;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        score += 10;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        score += 10;
    }
    
    // Penalize patterns (overly simplified, could be improved)
    // Repeated characters
    if password.chars().collect::<std::collections::HashSet<_>>().len() < password.len() / 2 {
        score -= 10;
    }
    
    // Ensure score is between 0-100
    score.clamp(0, 100)
}

/// Derive a key from a password with a specific context
pub fn derive_key_from_password(password: &str, context: &str) -> Result<Vec<u8>> {
    // Create a salt using the context
    let salt_data = format!("RUSTVAULT_{}", context);
    
    // Hash the password with Argon2id
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(&base64::engine::general_purpose::STANDARD.encode(salt_data.as_bytes()))
        .map_err(|e| CryptoError::HashingError(e.to_string()))?;
    
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingError(e.to_string()))?;
    
    // Use the hash bytes as the key
    let hash_bytes = password_hash.hash.unwrap().as_bytes().to_vec();
    
    // Ensure we have at least 32 bytes (for AES-256)
    if hash_bytes.len() < 32 {
        return Err(CryptoError::KeySizeError("Derived key too short".to_string()));
    }
    
    Ok(hash_bytes[0..32].to_vec())
}

/// Encrypt arbitrary data using the provided key
pub fn encrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    // Generate a random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    
    // Encrypt the data
    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher.encrypt(&nonce.into(), data)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    
    // Combine nonce and ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend(ciphertext);
    
    Ok(result)
}

/// Decrypt data that was encrypted with encrypt_data
pub fn decrypt_data(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    // Ensure data is long enough to contain nonce + tag
    if data.len() < 12 + 16 {
        return Err(CryptoError::DecryptionError("Data too short".to_string()));
    }
    
    // Split data into nonce and ciphertext
    let nonce = &data[0..12];
    let ciphertext = &data[12..];
    
    // Decrypt the data
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher.decrypt(nonce.into(), ciphertext)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    Ok(plaintext)
}