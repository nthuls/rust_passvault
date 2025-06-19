// src/utils/io.rs
// use std::fs;
use std::path::PathBuf;
use dirs;

/// Get the application config directory
pub fn get_app_config_dir() -> Option<std::path::PathBuf> {
    if let Some(proj_dirs) = directories::ProjectDirs::from("com", "rustvault", "rustvault") {
        let config_dir = proj_dirs.config_dir();
        
        // Create the directory if it doesn't exist
        if !config_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(config_dir) {
                log::error!("Failed to create config directory: {}", e);
                return None;
            }
        }
        
        Some(config_dir.to_path_buf())
    } else {
        log::error!("Could not determine config directory");
        None
    }
}