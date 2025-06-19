// src/privacy/mod.rs - Privacy Manager

use std::path::{Path, PathBuf};
use std::fs;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use crate::utils;
use crate::db::Database;
use std::collections::HashMap;
pub mod levels;
pub mod profiles;
pub mod browsers;
pub mod fingerprint;
pub mod storage;
pub mod network;
use std::str::FromStr;
use levels::{ProtectionLevel, PrivacySettings};
use profiles::PrivacyProfile;
use utoipa::ToSchema;

#[derive(Error, Debug)]
pub enum PrivacyError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),
    
    #[error("Browser error: {0}")]
    BrowserError(String),
    
    #[error("Firefox not found")]
    FirefoxNotFound,
    
    #[error("Invalid protection level: {0}")]
    InvalidLevel(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] crate::db::DbError),
}

pub type Result<T> = std::result::Result<T, PrivacyError>;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct PrivacyStatus {
    pub protection_level: ProtectionLevel,
    pub browser_hardening: bool,
    pub firefox_hardened: bool,
    pub fingerprint_protection: bool,
    pub storage_protection: bool,
    pub network_protection: bool,
}

pub struct PrivacyManager {
    profiles_dir: PathBuf,
    config_dir: PathBuf,
    active_profile: PrivacyProfile,
}

impl PrivacyManager {
    pub fn new() -> Result<Self> {
        // Get app config directory
        let config_dir = utils::get_app_config_dir()
            .ok_or_else(|| PrivacyError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Config directory not found"
            )))?;
        
        // Set up profiles directory
        let profiles_dir = config_dir.join("profiles");
        if !profiles_dir.exists() {
            fs::create_dir_all(&profiles_dir)?;
        }
        
        // Set up custom profiles directory
        let custom_profiles_dir = profiles_dir.join("custom");
        if !custom_profiles_dir.exists() {
            fs::create_dir_all(&custom_profiles_dir)?;
        }
        
        // Create standard profiles if they don't exist
        Self::create_default_profiles(&profiles_dir)?;
        
        // Load active profile (or use standard as default)
        let active_profile = Self::load_active_profile(&config_dir)?;
        
        Ok(Self {
            profiles_dir,
            config_dir,
            active_profile,
        })
    }
    
    // Get the current privacy status
    pub fn get_status(&self) -> PrivacyStatus {
        PrivacyStatus {
            protection_level: self.active_profile.level.clone(),
            browser_hardening: self.active_profile.settings.browser_hardening,
            firefox_hardened: self.is_firefox_hardened().unwrap_or(false),
            fingerprint_protection: self.active_profile.settings.fingerprint.is_active(),
            storage_protection: self.active_profile.settings.storage.is_active(),
            network_protection: self.active_profile.settings.network.is_active(),
        }
    }
    
    // Get current protection level
    pub fn get_protection_level(&self) -> ProtectionLevel {
        self.active_profile.level.clone()
    }
    
    // Set protection level
    pub fn set_protection_level(&mut self, level: ProtectionLevel) -> Result<()> {
        match level {
            ProtectionLevel::Basic | ProtectionLevel::Standard | ProtectionLevel::Strict => {
                // Load predefined profile for this level
                let profile_path = self.profiles_dir.join(format!("{}.json", level.to_string().to_lowercase()));
                if !profile_path.exists() {
                    return Err(PrivacyError::ProfileNotFound(format!("Predefined profile for {} level not found", level)));
                }
                
                let profile = profiles::PrivacyProfile::load_from_file(&profile_path)?;
                self.active_profile = profile;
                self.save_active_profile()?;
            },
            ProtectionLevel::Custom => {
                // Just update the level, keep current settings
                self.active_profile.level = ProtectionLevel::Custom;
                self.save_active_profile()?;
            }
        }
        
        Ok(())
    }
    
    // List available profiles
    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let mut profiles = Vec::new();
        
        // Add standard profiles
        for level in &[ProtectionLevel::Basic, ProtectionLevel::Standard, ProtectionLevel::Strict] {
            profiles.push(level.to_string());
        }
        
        // Add custom profiles from the custom directory
        let custom_dir = self.profiles_dir.join("custom");
        if custom_dir.exists() {
            for entry in fs::read_dir(custom_dir)? {
                let entry = entry?;
                if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                    if let Some(name) = entry.path().file_stem().and_then(|stem| stem.to_str()) {
                        profiles.push(name.to_string());
                    }
                }
            }
        }
        
        Ok(profiles)
    }
    
    // Get a specific profile
    pub fn get_profile(&self, name: &str) -> Result<PrivacyProfile> {
        // Check if it's a standard profile
        if let Ok(level) = levels::ProtectionLevel::from_str(name) {
            let profile_path = self.profiles_dir.join(format!("{}.json", level.to_string().to_lowercase()));
            if profile_path.exists() {
                return profiles::PrivacyProfile::load_from_file(&profile_path);
            }
        }
        
        // Check custom profiles
        let custom_path = self.profiles_dir.join("custom").join(format!("{}.json", name));
        if custom_path.exists() {
            return profiles::PrivacyProfile::load_from_file(&custom_path);
        }
        
        Err(PrivacyError::ProfileNotFound(name.to_string()))
    }
    
    // Create a new custom profile
    pub fn create_profile(&self, profile: PrivacyProfile) -> Result<()> {
        // Ensure it has a unique name
        let name = profile.name.clone();
        let custom_path = self.profiles_dir.join("custom").join(format!("{}.json", name));
        
        // Don't overwrite standard profiles
        if levels::ProtectionLevel::from_str(&name).is_ok() {
            return Err(PrivacyError::InvalidLevel(format!(
                "Cannot create a custom profile with a standard protection level name: {}", name
            )));
        }
        
        // Save the profile
        profile.save_to_file(&custom_path)?;
        
        Ok(())
    }
    
    // Update an existing profile
    pub fn update_profile(&mut self, name: &str, profile: PrivacyProfile) -> Result<()> {
        // Check if this is the active profile
        let is_active = name == self.active_profile.name;
        
        // Handle standard profiles differently
        if levels::ProtectionLevel::from_str(name).is_ok() {
            return Err(PrivacyError::InvalidLevel(format!(
                "Cannot modify standard protection profile: {}", name
            )));
        }
        
        // Check if profile exists
        let custom_path = self.profiles_dir.join("custom").join(format!("{}.json", name));
        if !custom_path.exists() {
            return Err(PrivacyError::ProfileNotFound(name.to_string()));
        }
        
        // Save the updated profile
        profile.save_to_file(&custom_path)?;
        
        // Update active profile if needed
        if is_active {
            self.active_profile = profile;
            self.save_active_profile()?;
        }
        
        Ok(())
    }
    
    // Delete a custom profile
    pub fn delete_profile(&self, name: &str) -> Result<()> {
        // Cannot delete standard profiles
        if levels::ProtectionLevel::from_str(name).is_ok() {
            return Err(PrivacyError::InvalidLevel(format!(
                "Cannot delete standard protection profile: {}", name
            )));
        }
        
        // Check if profile exists
        let custom_path = self.profiles_dir.join("custom").join(format!("{}.json", name));
        if !custom_path.exists() {
            return Err(PrivacyError::ProfileNotFound(name.to_string()));
        }
        
        // Delete the profile
        fs::remove_file(custom_path)?;
        
        Ok(())
    }
    
    // Apply Firefox hardening
    pub fn harden_firefox(&self) -> Result<Vec<String>> {
        let firefox_hardener = browsers::firefox::FirefoxHardener::new()?;
        
        let level = self.active_profile.level.clone();
        let firefox_settings = &self.active_profile.settings.firefox;
        
        firefox_hardener.apply_hardening(level, firefox_settings)
    }
    
    // Check if Firefox is hardened
    pub fn is_firefox_hardened(&self) -> Result<bool> {
        let firefox_hardener = browsers::firefox::FirefoxHardener::new()?;
        firefox_hardener.is_hardened()
    }
    
    // Clean privacy data
    pub fn clean_privacy_data(&self, options: storage::CleaningOptions) -> Result<Vec<String>> {
        let mut cleaned_items = Vec::new();
        
        // Clean browser data
        if options.clear_cookies || options.clear_history || 
           options.clear_cache || options.clear_local_storage {
            // Clean Firefox data
            let firefox_cleaner = storage::BrowserCleaner::new()?;
            
            if let Ok(mut items) = firefox_cleaner.clean_firefox_data(options.clone()) {
                cleaned_items.append(&mut items);
            }
        }
        
        Ok(cleaned_items)
    }
    
    // Get fingerprint settings
    pub fn get_fingerprint_settings(&self) -> fingerprint::FingerprintSettings {
        self.active_profile.settings.fingerprint.clone()
    }
    
    // Set fingerprint settings
    pub fn set_fingerprint_settings(&mut self, settings: fingerprint::FingerprintSettings) -> Result<()> {
        self.active_profile.settings.fingerprint = settings;
        self.active_profile.level = ProtectionLevel::Custom;
        self.save_active_profile()?;
        Ok(())
    }
    
    // Get storage settings
    pub fn get_storage_settings(&self) -> storage::StorageSettings {
        self.active_profile.settings.storage.clone()
    }
    
    // Set storage settings
    pub fn set_storage_settings(&mut self, settings: storage::StorageSettings) -> Result<()> {
        self.active_profile.settings.storage = settings;
        self.active_profile.level = ProtectionLevel::Custom;
        self.save_active_profile()?;
        Ok(())
    }
    
    // Get network settings
    pub fn get_network_settings(&self) -> network::NetworkSettings {
        self.active_profile.settings.network.clone()
    }
    
    // Set network settings
    pub fn set_network_settings(&mut self, settings: network::NetworkSettings) -> Result<()> {
        self.active_profile.settings.network = settings;
        self.active_profile.level = ProtectionLevel::Custom;
        self.save_active_profile()?;
        Ok(())
    }
    
    // Configure DNS protection
    pub fn configure_dns(&self, dns_settings: network::dns::DnsSettings) -> Result<()> {
        let dns_configurator = network::dns::DnsConfigurator::new()?;
        dns_configurator.apply_settings(&dns_settings)?;
        Ok(())
    }
    
    // Helper method to create default profiles
    fn create_default_profiles(profiles_dir: &Path) -> Result<()> {
        // Create Basic profile
        let basic_path = profiles_dir.join("basic.json");
        if !basic_path.exists() {
            let basic_profile = PrivacyProfile {
                name: "Basic".to_string(),
                description: "Essential protections with minimal site breakage".to_string(),
                level: ProtectionLevel::Basic,
                settings: ProtectionLevel::Basic.get_default_settings(),
            };
            basic_profile.save_to_file(&basic_path)?;
        }
        
        // Create Standard profile
        let standard_path = profiles_dir.join("standard.json");
        if !standard_path.exists() {
            let standard_profile = PrivacyProfile {
                name: "Standard".to_string(),
                description: "Balanced protection for everyday browsing".to_string(),
                level: ProtectionLevel::Standard,
                settings: ProtectionLevel::Standard.get_default_settings(),
            };
            standard_profile.save_to_file(&standard_path)?;
        }
        
        // Create Strict profile
        let strict_path = profiles_dir.join("strict.json");
        if !strict_path.exists() {
            let strict_profile = PrivacyProfile {
                name: "Strict".to_string(),
                description: "Maximum privacy at the cost of some functionality".to_string(),
                level: ProtectionLevel::Strict,
                settings: ProtectionLevel::Strict.get_default_settings(),
            };
            strict_profile.save_to_file(&strict_path)?;
        }
        
        // Create Banking profile
        let banking_path = profiles_dir.join("custom").join("banking.json");
        if !banking_path.exists() {
            let banking_profile = PrivacyProfile {
                name: "Banking".to_string(),
                description: "Enhanced protection for financial sites".to_string(),
                level: ProtectionLevel::Custom,
                settings: {
                    let mut settings = ProtectionLevel::Strict.get_default_settings();
                    // Allow cookies for banking sites
                    settings.storage.cookie_management = false;
                    settings
                },
            };
            banking_profile.save_to_file(&banking_path)?;
        }
        
        // Create Workspace profile
        let workspace_path = profiles_dir.join("custom").join("workspace.json");
        if !workspace_path.exists() {
            let workspace_profile = PrivacyProfile {
                name: "Workspace".to_string(),
                description: "Optimized for work environments".to_string(),
                level: ProtectionLevel::Custom,
                settings: {
                    let mut settings = ProtectionLevel::Standard.get_default_settings();
                    // Less restrictive for work tools
                    settings.fingerprint.webgl_protection = false;
                    settings.storage.localstorage_clearing = false;
                    settings
                },
            };
            workspace_profile.save_to_file(&workspace_path)?;
        }
        
        Ok(())
    }
    
    // Load the active profile
    fn load_active_profile(config_dir: &Path) -> Result<PrivacyProfile> {
        let active_profile_path = config_dir.join("active_profile.json");
        
        if active_profile_path.exists() {
            profiles::PrivacyProfile::load_from_file(&active_profile_path)
        } else {
            // Default to Standard profile
            let standard_path = config_dir.join("profiles").join("standard.json");
            if standard_path.exists() {
                let profile = profiles::PrivacyProfile::load_from_file(&standard_path)?;
                // Save as active profile
                profile.save_to_file(&active_profile_path)?;
                Ok(profile)
            } else {
                // Create a new Standard profile
                let profile = PrivacyProfile {
                    name: "Standard".to_string(),
                    description: "Balanced protection for everyday browsing".to_string(),
                    level: ProtectionLevel::Standard,
                    settings: ProtectionLevel::Standard.get_default_settings(),
                };
                profile.save_to_file(&active_profile_path)?;
                Ok(profile)
            }
        }
    }
    
    // Save the active profile
    fn save_active_profile(&self) -> Result<()> {
        let active_profile_path = self.config_dir.join("active_profile.json");
        self.active_profile.save_to_file(&active_profile_path)?;
        Ok(())
    }

    // Test fingerprint protection
    pub fn test_fingerprint_protection(&self) -> Result<HashMap<String, bool>> {
        let mut results = HashMap::new();
        
        // Check if Firefox is hardened
        let firefox_hardened = self.is_firefox_hardened().unwrap_or(false);
        results.insert("firefox_hardened".to_string(), firefox_hardened);
        
        // User Agent protection
        results.insert("user_agent".to_string(), 
            firefox_hardened && self.active_profile.settings.firefox.enable_do_not_track);
        
        // Canvas fingerprinting protection
        results.insert("canvas".to_string(), 
            self.active_profile.settings.fingerprint.canvas_protection);
        
        // WebGL fingerprinting protection
        results.insert("webgl".to_string(), 
            self.active_profile.settings.fingerprint.webgl_protection);
        
        // Audio fingerprinting protection
        results.insert("audio".to_string(), 
            self.active_profile.settings.fingerprint.audio_protection);
        
        // Font fingerprinting protection
        results.insert("fonts".to_string(), 
            self.active_profile.settings.fingerprint.font_protection);
        
        // Hardware fingerprinting protection
        results.insert("hardware".to_string(), 
            self.active_profile.settings.fingerprint.hardware_protection);
        
        // Time zone protection (part of Firefox RFP)
        results.insert("timezone".to_string(), firefox_hardened);
        
        // Language/platform protection
        results.insert("language".to_string(), firefox_hardened);
        
        // Do Not Track header
        results.insert("dnt_header".to_string(), 
            firefox_hardened && self.active_profile.settings.firefox.enable_do_not_track);
        
        // Add more tests as needed
        
        Ok(results)
    }
  
}