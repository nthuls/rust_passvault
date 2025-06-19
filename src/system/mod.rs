// src/system/mod.rs
use std::path::Path;
use std::process::Command;
use sysinfo::{System, SystemExt, DiskExt};
use crate::db::Database;
use crate::privacy::PrivacyManager;
use thiserror::Error;
pub mod firejail;
pub use firejail::{FirejailManager, FirejailError, LaunchBrowserRequest};
use utoipa::ToSchema;

#[derive(Error, Debug)]
pub enum SystemError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Failed to execute command: {0}")]
    CommandError(String),
    
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Privacy error: {0}")]
    PrivacyError(String),
    
    #[error("Firejail not installed")]
    FirejailNotInstalled,
    
    #[error("Browser not found: {0}")]
    BrowserNotFound(String),
}

pub type Result<T> = std::result::Result<T, SystemError>;

#[derive(serde::Serialize, serde::Deserialize, ToSchema)]
pub struct SystemStatus {
    // Vault status
    pub locked: bool,
    pub password_count: usize,
    pub category_count: usize,
    
    // Database info
    pub database_type: String,
    pub database_size_bytes: u64,
    
    // System info
    pub os_info: String,
    pub free_disk_space_bytes: u64,
    pub total_disk_space_bytes: u64,
    
    // Application info
    pub version: String,
    pub last_backup: Option<String>,
    
    // Privacy status
    pub privacy_protection_level: String,
    pub browser_hardening_active: bool,
}

pub struct SystemManager {
    system: System,
}

impl SystemManager {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        
        Self { system }
    }
    
    pub async fn get_system_status(&mut self, db: &Database, vault_locked: bool) -> Result<SystemStatus> {
        // Refresh system info
        self.system.refresh_all();

        // Get password and category counts
        let (password_count, category_count) = if vault_locked {
            (0, 0)
        } else {
            (
                db.get_password_count().await?,
                db.get_all_categories().await?.len(),
            )
        };

        // Get database type string
        let database_type = db.get_backend_type().to_string();

        // Get database size
        let database_size_bytes = if let Some(sqlite) = db.get_sqlite_backend() {
            if let Some(path) = sqlite.get_db_path() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    metadata.len()
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        };

        // Get system info
        let os_info = format!(
            "{} {}",
            self.system.name().unwrap_or_else(|| "Unknown".to_string()),
            self.system.os_version().unwrap_or_else(|| "".to_string())
        );

        // Get disk space info for the app data directory
        let config_dir = crate::utils::get_app_config_dir()
            .ok_or_else(|| SystemError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Config directory not found",
            )))?;

        let mut free_space = 0;
        let mut total_space = 0;

        for disk in self.system.disks() {
            let mount_point = disk.mount_point();

            if config_dir.starts_with(mount_point) {
                free_space = disk.available_space();
                total_space = disk.total_space();
                break;
            }
        }

        // Get app version
        let version = env!("CARGO_PKG_VERSION").to_string();

        // Get last backup time
        let last_backup = if let Ok(backup_dir) = std::path::PathBuf::from(&config_dir).join("backups").canonicalize() {
            use chrono::{DateTime, Utc};
            use std::time::SystemTime;

            let mut latest: Option<DateTime<Utc>> = None;

            if let Ok(entries) = std::fs::read_dir(backup_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() && entry.path().extension().map_or(false, |ext| ext == "vault") {
                            if let Ok(modified) = metadata.modified() {
                                let datetime = DateTime::<Utc>::from(modified);
                                if latest.map_or(true, |latest_time| datetime > latest_time) {
                                    latest = Some(datetime);
                                }
                            }
                        }
                    }
                }
            }

            latest.map(|dt| dt.to_rfc3339())
        } else {
            None
        };

        // Get privacy status
        let privacy_manager = PrivacyManager::new()
            .map_err(|e| SystemError::PrivacyError(e.to_string()))?;

        let privacy_status = privacy_manager.get_status();

        Ok(SystemStatus {
            locked: vault_locked,
            password_count,
            category_count,
            database_type,
            database_size_bytes,
            os_info,
            free_disk_space_bytes: free_space,
            total_disk_space_bytes: total_space,
            version,
            last_backup,
            privacy_protection_level: format!("{:?}", privacy_status.protection_level),
            browser_hardening_active: privacy_status.browser_hardening,
        })
    }
}