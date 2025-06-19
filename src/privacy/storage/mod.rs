// src/privacy/storage/mod.rs
use serde::{Serialize, Deserialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct StorageSettings {
    pub cookie_management: bool,
    pub localstorage_clearing: bool,
    pub cache_management: bool,
    pub evercookie_mitigation: bool,
}

impl StorageSettings {
    // Check if any storage protection is active
    pub fn is_active(&self) -> bool {
        self.cookie_management || 
        self.localstorage_clearing || 
        self.cache_management || 
        self.evercookie_mitigation
    }
}

#[derive(Clone, Debug)]
pub struct CleaningOptions {
    pub clear_cookies: bool,
    pub clear_history: bool,
    pub clear_cache: bool,
    pub clear_local_storage: bool,
}

pub struct BrowserCleaner {
    firefox_profiles: Vec<(String, std::path::PathBuf)>,
}

impl BrowserCleaner {
    pub fn new() -> Result<Self, super::PrivacyError> {
        // Find Firefox profiles
        let profiler = crate::firefox::profile::FirefoxProfiler::new();
        let firefox_profiles = profiler.find_profiles();
        
        Ok(Self { firefox_profiles })
    }
    
    // Clean Firefox data
    pub fn clean_firefox_data(&self, options: CleaningOptions) -> Result<Vec<String>, super::PrivacyError> {
        let mut cleaned_items = Vec::new();
        
        for (profile_name, profile_path) in &self.firefox_profiles {
            if options.clear_cookies {
                self.clean_firefox_cookies(&profile_path)?;
                cleaned_items.push(format!("Firefox cookies ({})", profile_name));
            }
            
            if options.clear_history {
                self.clean_firefox_history(&profile_path)?;
                cleaned_items.push(format!("Firefox history ({})", profile_name));
            }
            
            if options.clear_cache {
                self.clean_firefox_cache(&profile_path)?;
                cleaned_items.push(format!("Firefox cache ({})", profile_name));
            }
            
            if options.clear_local_storage {
                self.clean_firefox_storage(&profile_path)?;
                cleaned_items.push(format!("Firefox storage ({})", profile_name));
            }
        }
        
        Ok(cleaned_items)
    }
    
    // Clean Firefox cookies
    fn clean_firefox_cookies(&self, profile_path: &std::path::Path) -> Result<(), super::PrivacyError> {
        let cookies_file = profile_path.join("cookies.sqlite");
        if cookies_file.exists() {
            // Use SQLite to clean cookies
            match rusqlite::Connection::open(&cookies_file) {
                Ok(conn) => {
                    // First try to delete all cookies
                    let _ = conn.execute("DELETE FROM moz_cookies", []);
                    // Then vacuum the database to reclaim space
                    let _ = conn.execute("VACUUM", []);
                },
                Err(e) => {
                    log::warn!("Failed to open cookies database: {}", e);
                    // If we can't open the database, try to delete it
                    // Firefox will recreate it when needed
                    let _ = std::fs::remove_file(&cookies_file);
                }
            }
        }
        Ok(())
    }
    
    // Clean Firefox history
    fn clean_firefox_history(&self, profile_path: &std::path::Path) -> Result<(), super::PrivacyError> {
        let places_file = profile_path.join("places.sqlite");
        if places_file.exists() {
            match rusqlite::Connection::open(&places_file) {
                Ok(conn) => {
                    // Delete history entries
                    let _ = conn.execute("DELETE FROM moz_places", []);
                    let _ = conn.execute("DELETE FROM moz_historyvisits", []);
                    // Delete downloads
                    let _ = conn.execute("DELETE FROM moz_downloads", []);
                    // Vacuum the database
                    let _ = conn.execute("VACUUM", []);
                },
                Err(e) => {
                    log::warn!("Failed to open places database: {}", e);
                    // If we can't open the database, try to delete it
                    let _ = std::fs::remove_file(&places_file);
                }
            }
        }
        Ok(())
    }
    
    // Clean Firefox cache
    fn clean_firefox_cache(&self, profile_path: &std::path::Path) -> Result<(), super::PrivacyError> {
        // Firefox cache is stored in the cache2 directory
        let cache_dir = profile_path.join("cache2");
        if cache_dir.exists() {
            // Remove the entire cache directory
            // Firefox will recreate it when needed
            let _ = std::fs::remove_dir_all(&cache_dir);
            let _ = std::fs::create_dir(&cache_dir);
        }
        Ok(())
    }
    
    // Clean Firefox storage (localStorage, IndexedDB, etc.)
    fn clean_firefox_storage(&self, profile_path: &std::path::Path) -> Result<(), super::PrivacyError> {
        // LocalStorage
        let storage_dir = profile_path.join("storage");
        if storage_dir.exists() {
            let _ = std::fs::remove_dir_all(&storage_dir);
            let _ = std::fs::create_dir(&storage_dir);
        }
        
        // IndexedDB
        let indexeddb_dir = profile_path.join("indexedDB");
        if indexeddb_dir.exists() {
            let _ = std::fs::remove_dir_all(&indexeddb_dir);
            let _ = std::fs::create_dir(&indexeddb_dir);
        }
        
        Ok(())
    }
}