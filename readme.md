# Initialize PostgreSQL

```sql
-- Run this in your PostgreSQL shell or pgAdmin

-- Create database
CREATE DATABASE passwordvault;

-- Connect to the database
\c passwordvault

-- Create extension for UUID support (if not already available)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create the passwords table
CREATE TABLE IF NOT EXISTS passwords (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site TEXT NOT NULL,
  username TEXT NOT NULL,
  password BYTEA NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_passwords_site ON passwords(site);
```

# How to Run the Application

1. Install PostgreSQL and set up the database using the SQL above
2. Update the `.env` file with your PostgreSQL credentials
3. Build and run the project:

```bash
cargo build
cargo run
```

# Security Notes

- The master password is never stored anywhere
- All passwords are encrypted with AES-256-GCM before storage
- Key derivation uses Argon2id with secure parameters
- For a production app, you would want to:
  - Add proper error handling with user-friendly messages
  - Implement a proper salt generation and storage mechanism
  - Add a password generator feature
  - Add export/import functionality with encrypted backups
  - Add password history tracking
  - Implement proper memory clearing for sensitive data
# .env
```
DATABASE_URL=postgres://postgres:postgres@localhost/passwordvault
```

# Cargo.toml
```
[package]
name = "rust_passvault"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono"] }
argon2 = "0.5"
aes-gcm = "0.10"
rand = "0.8"
base64 = "0.21"
dotenvy = "0.15"
inquire = "0.6"
uuid = { version = "1.4", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1.0"


```
```
// src/crypto.rs
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use std::error::Error;

const SALT: &[u8] = b"rustypasswordvaultsalt"; // Fixed salt for simplicity

pub fn derive_key(master_password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // Convert the fixed salt to SaltString
    let salt = SaltString::from_b64_encoded("cnVzdHlwYXNzd29yZHZhdWx0c2FsdA==")
        .unwrap_or_else(|_| SaltString::generate(&mut OsRng));

    // Configure Argon2id
    let argon2 = Argon2::default();
    
    // Hash the password (derive key)
    let password_hash = argon2.hash_password(master_password.as_bytes(), &salt)?;
    
    // Extract and return the raw hash bytes (to use as encryption key)
    Ok(password_hash.hash.unwrap().as_bytes().to_vec())
}

pub fn encrypt_password(key: &[u8], plaintext: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    // Create a proper key for AES-GCM
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    
    // Create the cipher
    let cipher = Aes256Gcm::new(aes_key);
    
    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the plaintext
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())?;
    
    // Combine nonce and ciphertext to create the final encrypted data
    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ciphertext);
    
    Ok(encrypted)
}

pub fn decrypt_password(key: &[u8], ciphertext: &[u8]) -> Result<String, Box<dyn Error>> {
    // Ensure the ciphertext is at least as long as the nonce
    if ciphertext.len() <= 12 {
        return Err("Invalid ciphertext length".into());
    }
    
    // Split the ciphertext into nonce and actual ciphertext
    let (nonce, actual_ciphertext) = ciphertext.split_at(12);
    
    // Create a proper key for AES-GCM
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    
    // Create the cipher
    let cipher = Aes256Gcm::new(aes_key);
    
    // Decrypt the ciphertext
    let plaintext = cipher.decrypt(nonce.into(), actual_ciphertext)?;
    
    // Convert the plaintext back to a string
    let password = String::from_utf8(plaintext)?;
    
    Ok(password)
}
```

```
// src/db.rs
use sqlx::{postgres::PgPoolOptions, Pool, Postgres, Row};
use std::error::Error;
use uuid::Uuid;

pub struct PasswordEntry {
    pub id: Uuid,
    pub site: String,
    pub username: String,
    pub password: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn init_db(db_url: &str) -> Result<Pool<Postgres>, Box<dyn Error>> {
    // Create a connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await?;

    // Ensure the table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS passwords (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password BYTEA NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#,
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn add_password(
    pool: &Pool<Postgres>,
    site: &str,
    username: &str,
    encrypted_password: &[u8],
) -> Result<(), Box<dyn Error>> {
    sqlx::query(
        r#"
        INSERT INTO passwords (site, username, password)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(site)
    .bind(username)
    .bind(encrypted_password)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_all_passwords(pool: &Pool<Postgres>) -> Result<Vec<PasswordEntry>, Box<dyn Error>> {
    let rows = sqlx::query(
        r#"
        SELECT id, site, username, password, created_at
        FROM passwords
        ORDER BY site ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let passwords = rows
        .iter()
        .map(|row| PasswordEntry {
            id: row.get("id"),
            site: row.get("site"),
            username: row.get("username"),
            password: row.get("password"),
            created_at: row.get("created_at"),
        })
        .collect();

    Ok(passwords)
}

pub async fn delete_password(pool: &Pool<Postgres>, id: Uuid) -> Result<(), Box<dyn Error>> {
    sqlx::query("DELETE FROM passwords WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}
```

```
// src/main.rs
use inquire::{Confirm, Password, Select, Text};
use std::error::Error;
use std::path::Path;

mod crypto;
mod db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("╔══════════════════════════════════════╗");
    println!("║           RUST PASSWORD VAULT        ║");
    println!("╚══════════════════════════════════════╝");

    // Load environment variables
    if Path::new(".env").exists() {
        dotenvy::dotenv().ok();
    }

    // Connect to database
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/passwordvault".to_string());
    let db_pool = db::init_db(&db_url).await?;

    // Ask for master password
    let master_password = Password::new("Enter your master password:")
        .with_display_mode(inquire::PasswordDisplayMode::Hidden)
        .prompt()?;

    // Derive the master key
    let master_key = crypto::derive_key(&master_password)?;

    loop {
        // Main menu
        println!("\n📋 Main Menu");
        let options = vec!["Add password", "View passwords", "Delete password", "Exit"];
        let selection = Select::new("Choose an option:", options).prompt()?;

        match selection {
            "Add password" => {
                let site = Text::new("Website or service:").prompt()?;
                let username = Text::new("Username or email:").prompt()?;
                let password = Password::new("Password:")
                    .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                    .prompt()?;

                let encrypted = crypto::encrypt_password(&master_key, &password)?;
                db::add_password(&db_pool, &site, &username, &encrypted).await?;
                println!("✅ Password added successfully!");
            }
            "View passwords" => {
                let passwords = db::get_all_passwords(&db_pool).await?;

                if passwords.is_empty() {
                    println!("❗ No passwords stored yet.");
                    continue;
                }

                let sites: Vec<String> = passwords.iter().map(|p| p.site.clone()).collect();
                let selection = Select::new("Select a site to view details:", sites).prompt()?;

                let selected = passwords
                    .iter()
                    .find(|p| p.site == selection)
                    .expect("Selected item not found");

                let decrypted = crypto::decrypt_password(&master_key, &selected.password)?;

                println!("\n🔐 Password Details");
                println!("Site: {}", selected.site);
                println!("Username: {}", selected.username);
                println!("Password: {}", decrypted);
                println!("Created: {}\n", selected.created_at);

                // Wait for user to press enter
                let _ = Text::new("Press enter to continue...").prompt();
            }
            "Delete password" => {
                let passwords = db::get_all_passwords(&db_pool).await?;

                if passwords.is_empty() {
                    println!("❗ No passwords stored yet.");
                    continue;
                }

                let sites: Vec<String> = passwords.iter().map(|p| p.site.clone()).collect();
                let selection = Select::new("Select a site to delete:", sites).prompt()?;

                let confirm = Confirm::new(&format!("Are you sure you want to delete the entry for '{}'?", selection))
                    .with_default(false)
                    .prompt()?;

                if confirm {
                    let selected = passwords
                        .iter()
                        .find(|p| p.site == selection)
                        .expect("Selected item not found");

                    db::delete_password(&db_pool, selected.id).await?;
                    println!("✅ Password deleted successfully!");
                }
            }
            "Exit" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
```
# STRUCTURE 

```
rust_passvault/
├── src/
│   ├── main.rs              # Application entry point and TUI interface
│   ├── db.rs                # Database operations (PostgreSQL)
│   ├── crypto.rs            # Encryption/decryption and key derivation
│   ├── models.rs            # Shared data structures
│   ├── firefox/
│   │   ├── mod.rs           # Module exports
│   │   ├── profile.rs       # Firefox profile detection
│   │   ├── credentials.rs   # Parsing credential files (logins.json/sqlite)
│   │   └── nss.rs           # NSS library interaction for decryption
│   ├── importers/
│   │   ├── mod.rs           # Module exports
│   │   ├── firefox.rs       # Firefox import logic
│   │   └── csv.rs           # CSV import/export
│   ├── generators/
│   │   ├── mod.rs           # Module exports
│   │   └── password.rs      # Password generation logic
│   └── utils.rs             # Utility functions
├── migrations/              # SQL migrations
│   ├── 20250519_initial.sql # Initial schema setup
│   └── 20250519_tags.sql    # Tags/categories support
├── .env                     # Environment configuration
├── Cargo.toml               # Dependencies and project metadata
└── README.md                # Documentation
```

## File Responsibilities

### Core Application Files

**main.rs**
- Application entry point
- TUI interface using `inquire`
- Command routing and user interaction
- Main menu and submenus

**db.rs**
- Database connection and initialization
- CRUD operations for passwords
- Transaction management
- Category/tag support

**crypto.rs**
- Key derivation using Argon2id
- Encryption/decryption using AES-GCM
- Secure random generation
- Password strength analysis

**models.rs**
- Shared data structures
- Password entry struct
- Category/tag structs
- Search filters

**utils.rs**
- Helper functions
- Error handling
- Logging
- Path handling across platforms

### Firefox Integration Files

**firefox/mod.rs**
- Exports from the Firefox module
- High-level interface for Firefox functionality

**firefox/profile.rs**
- Detect Firefox installations
- Parse profiles.ini
- Find and list available profiles
- Determine profile paths across platforms

**firefox/credentials.rs**
- Parse logins.json or signons.sqlite
- Extract encrypted credentials
- Handle different Firefox versions

**firefox/nss.rs**
- FFI bindings to NSS libraries
- Dynamic loading of NSS on different platforms
- Decoders for Firefox's encryption

### Import/Export Files

**importers/mod.rs**
- Exports from importers module
- Common import/export interfaces

**importers/firefox.rs**
- High-level logic for Firefox import
- Mapping Firefox data to our vault format

**importers/csv.rs**
- CSV import/export functionality
- Standardized format for backups

### Password Generation Files

**generators/mod.rs**
- Exports from generators module

**generators/password.rs**
- Strong password generation
- Customizable password policies
- Memorable password options

## Database Schema

Our PostgreSQL schema will include:

```sql
-- Main passwords table
CREATE TABLE passwords (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site TEXT NOT NULL,
  username TEXT NOT NULL,
  password BYTEA NOT NULL,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Categories/tags
CREATE TABLE categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE
);

-- Password-category relationship
CREATE TABLE password_categories (
  password_id UUID REFERENCES passwords(id) ON DELETE CASCADE,
  category_id UUID REFERENCES categories(id) ON DELETE CASCADE,
  PRIMARY KEY (password_id, category_id)
);

-- Indexes
CREATE INDEX idx_passwords_site ON passwords(site);
CREATE INDEX idx_password_categories ON password_categories(password_id);
```
# 🛡️ Rust PassVault

A secure, fast, and fully offline password vault written in Rust. Stores encrypted credentials in PostgreSQL using AES-GCM and Argon2id.

## ✅ Project Bootstrapping

### Step 1: Create the Project

```bash
cargo new rust_passvault
cd rust_passvault
```

### Step 2: Install `sqlx-cli`

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

### Step 3: Set Up `.env`

```env
DATABASE_URL=postgres://rust_socdev:2password@100.113.207.76/password_vault
```

### Step 4: Create the Database (from `psql`)

```sql
CREATE USER rust_socdev WITH PASSWORD '2password';
CREATE DATABASE password_vault OWNER rust_socdev;
```

### Step 5: Verify Access

```bash
psql -U rust_socdev -h 100.113.207.76 -d password_vault
```

## 🗃️ Migrations (sqlx)

```bash
sqlx migrate add init
# edit the migration SQL with table creation
sqlx migrate run
```

## 📦 Dependencies (`Cargo.toml`)

```toml
[package]
name = "rust_passvault"
version = "0.1.0"
edition = "2021"

[dependencies]
# Database
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono", "json"] }
tokio = { version = "1", features = ["full"] }

# Encryption
argon2 = "0.5"
aes-gcm = "0.10"
rand = "0.8"
base64 = "0.21"

# TUI
inquire = "0.6"
console = "0.15"

# Firefox integration
libloading = "0.8"
ini = "1.3"
rusqlite = { version = "0.29", features = ["bundled"] }
serde_json = "1.0"

# Utilities
uuid = { version = "1.4", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
thiserror = "1.0"
dotenvy = "0.15"
log = "0.4"
env_logger = "0.10"
dirs = "5.0"

# Password generation
rand_chacha = "0.3"

#command line argumeny parser
clap = { version = "4", features = ["derive"] }
```

## 🚀 Run the App

```bash
cargo build
cargo run
```
