// src/cli/handlers.rs
use crate::db::Database;
use crate::models::PasswordEntry;
use crate::core::vault::Vault;
use std::error::Error;
use uuid::Uuid;
use std::sync::Arc;

// Handlers for CLI commands
pub async fn handle_unlock(db: &Database, master_password: &str) -> Result<String, Box<dyn Error>> {
    let db_arc = Arc::new(db.clone());
    let vault = Vault::new(db_arc);
    match vault.unlock(master_password).await {
        Ok(token) => Ok(token),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_list_passwords(vault: &Vault, token: &str) -> Result<Vec<PasswordEntry>, Box<dyn Error>> {
    match vault.get_all_passwords(token).await {
        Ok(passwords) => Ok(passwords),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_get_password(vault: &Vault, token: &str, id: Uuid) -> Result<PasswordEntry, Box<dyn Error>> {
    match vault.get_password_by_id(token, id).await {
        Ok(password) => Ok(password),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_add_password(
    vault: &Vault,
    token: &str,
    site: &str,
    username: &str,
    password: &str,
    notes: Option<&str>,
    categories: &[String],
) -> Result<Uuid, Box<dyn Error>> {
    match vault.add_password(token, site, username, password, notes, categories).await {
        Ok(id) => Ok(id),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_delete_password(vault: &Vault, token: &str, id: Uuid) -> Result<(), Box<dyn Error>> {
    match vault.delete_password(token, id).await {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_update_password(
    vault: &Vault,
    token: &str,
    id: Uuid,
    site: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    notes: Option<&str>,
    categories: Option<&[String]>,
) -> Result<(), Box<dyn Error>> {
    match vault.update_password(token, id, site, username, password, notes, categories).await {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn handle_web_password(vault: &Vault, token: &str) -> Result<(), Box<dyn Error>> {
    use inquire::Password;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    
    println!("🔐 Setting up web interface password");
    
    // Get the password
    let password = Password::new("Enter web interface password:")
        .with_display_mode(inquire::PasswordDisplayMode::Hidden)
        .prompt()?;
    
    // Confirm the password
    let confirm_password = Password::new("Confirm web interface password:")
        .with_display_mode(inquire::PasswordDisplayMode::Hidden)
        .prompt()?;
    
    if password != confirm_password {
        println!("❌ Passwords do not match. Please try again.");
        return Ok(());
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Hash the password with Argon2id
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
        .map_err(|e| Box::<dyn Error>::from(format!("Failed to hash password: {}", e)))?;
    
    // Store the hash in the database
    db.store_config_value("web_interface_password", password_hash.to_string().as_str()).await?;
    
    println!("✅ Web interface password set successfully!");
    
    Ok(())
}