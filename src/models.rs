// src/models.rs
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub site: String,
    pub username: String,
    pub password: Vec<u8>, // Encrypted password
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirefoxCredential {
    pub url: String,
    pub username: String,
    pub password: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordFilter {
    pub site_contains: Option<String>,
    pub username_contains: Option<String>,
    pub category: Option<String>,
}

// Password generation options
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordGenerationOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
    pub exclude_similar: bool,
    pub memorable: bool,
}

impl Default for PasswordGenerationOptions {
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
            exclude_similar: false,
            memorable: false,
        }
    }
}