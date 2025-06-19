// src/privacy/profiles.rs

use serde::{Serialize, Deserialize};
use std::path::Path;
use std::fs;
use super::levels::{ProtectionLevel, PrivacySettings};
use super::PrivacyError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivacyProfile {
    pub name: String,
    pub description: String,
    pub level: ProtectionLevel,
    pub settings: PrivacySettings,
}

impl PrivacyProfile {
    // Load a profile from a file
    pub fn load_from_file(path: &Path) -> Result<Self, PrivacyError> {
        let content = fs::read_to_string(path)?;
        let profile: Self = serde_json::from_str(&content)?;
        Ok(profile)
    }
    
    // Save a profile to a file
    pub fn save_to_file(&self, path: &Path) -> Result<(), PrivacyError> {
        let content = serde_json::to_string_pretty(self)?;
        
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        
        fs::write(path, content)?;
        Ok(())
    }
}