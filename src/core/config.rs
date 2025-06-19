// src/core/config.rs
use std::env;
use std::path::PathBuf;
use std::time::Duration;
use log::LevelFilter;

// Configuration for our password vault
#[derive(Debug, Clone)]
pub struct Config {
    // Database
    pub database_url: String,
    pub database_type: DatabaseType,
    
    // Encryption
    pub kdf_memory_cost: u32,
    pub kdf_time_cost: u32,
    pub kdf_parallelism: u32,
    
    // Session
    pub session_duration: Duration,
    pub session_dir: Option<PathBuf>,
    
    // Password Generation
    pub default_password_length: usize,
    pub default_password_exclude_similar: bool,
    
    // Application Settings
    pub auto_lock_timeout: Option<Duration>,
    pub max_failed_attempts: usize,
    pub failed_attempt_cooldown: Duration,
    
    // Backup Settings
    pub auto_backup: bool,
    pub backup_directory: PathBuf,
    pub backup_interval_days: u64,
    pub keep_backups: usize,
    
    // Firefox Integration
    pub firefox_profile_paths: Vec<PathBuf>,
    
    // Web Interface
    pub web_enabled: bool,
    pub web_port: u16,
    pub web_address: String,
    
    // Logging
    pub log_level: LevelFilter,
    pub log_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    SQLite,
    PostgreSQL,
    Auto,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Database
            database_url: "sqlite:./data/securevault.db".to_string(),
            database_type: DatabaseType::Auto,
            
            // Encryption
            kdf_memory_cost: 65536,
            kdf_time_cost: 3,
            kdf_parallelism: 4,
            
            // Session
            session_duration: Duration::from_secs(60 * 60), // 1 hour
            session_dir: None, // Will be initialized in load()
            
            // Password Generation
            default_password_length: 16,
            default_password_exclude_similar: true,
            
            // Application Settings
            auto_lock_timeout: Some(Duration::from_secs(5 * 60)),
            max_failed_attempts: 5,
            failed_attempt_cooldown: Duration::from_secs(300),
            
            // Backup Settings
            auto_backup: true,
            backup_directory: PathBuf::from("./backups"),
            backup_interval_days: 7,
            keep_backups: 5,
            
            // Firefox Integration
            firefox_profile_paths: Vec::new(),
            
            // Web Interface
            web_enabled: true,
            web_port: 5000,
            web_address: "127.0.0.1".to_string(),
            
            // Logging
            log_level: LevelFilter::Info,
            log_file: PathBuf::from("./securevault.log"),
        }
    }
}

impl Config {
    // Load configuration from environment variables
    pub fn load() -> Self {
        let mut config = Config::default();
        
        // Set session directory based on app config dir
        config.session_dir = crate::utils::get_app_config_dir()
            .map(|path| path.join("sessions"));
        
        // Database
        if let Ok(url) = env::var("DATABASE_URL") {
            config.database_url = url.clone();
            
            // Detect database type from URL
            if url.starts_with("sqlite:") {
                config.database_type = DatabaseType::SQLite;
            } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
                config.database_type = DatabaseType::PostgreSQL;
            }
        }
        
        if let Ok(db_type) = env::var("DATABASE_TYPE") {
            match db_type.to_lowercase().as_str() {
                "sqlite" => config.database_type = DatabaseType::SQLite,
                "postgresql" | "postgres" => config.database_type = DatabaseType::PostgreSQL,
                "auto" => config.database_type = DatabaseType::Auto,
                _ => log::warn!("Unknown database type '{}', using Auto", db_type),
            }
        }
        
        // Encryption
        if let Ok(val) = env::var("KDF_MEMORY_COST") {
            if let Ok(memory_cost) = val.parse() {
                config.kdf_memory_cost = memory_cost;
            }
        }
        
        if let Ok(val) = env::var("KDF_TIME_COST") {
            if let Ok(time_cost) = val.parse() {
                config.kdf_time_cost = time_cost;
            }
        }
        
        if let Ok(val) = env::var("KDF_PARALLELISM") {
            if let Ok(parallelism) = val.parse() {
                config.kdf_parallelism = parallelism;
            }
        }
        
        // Session
        if let Ok(val) = env::var("SESSION_DURATION_MINUTES") {
            if let Ok(duration) = val.parse::<u64>() {
                config.session_duration = Duration::from_secs(duration * 60);
            }
        }
        
        if let Ok(dir) = env::var("SESSION_DIRECTORY") {
            config.session_dir = Some(PathBuf::from(dir));
        }
        
        // Password Generation
        if let Ok(val) = env::var("DEFAULT_PASSWORD_LENGTH") {
            if let Ok(length) = val.parse() {
                config.default_password_length = length;
            }
        }
        
        if let Ok(val) = env::var("DEFAULT_PASSWORD_EXCLUDE_SIMILAR") {
            if let Ok(exclude) = val.parse() {
                config.default_password_exclude_similar = exclude;
            }
        }
        
        // Application Settings
        if let Ok(val) = env::var("AUTO_LOCK_TIMEOUT") {
            if let Ok(timeout) = val.parse::<u64>() {
                config.auto_lock_timeout = if timeout == 0 {
                    None
                } else {
                    Some(Duration::from_secs(timeout * 60))
                };
            }
        }
        
        if let Ok(val) = env::var("MAX_FAILED_ATTEMPTS") {
            if let Ok(attempts) = val.parse() {
                config.max_failed_attempts = attempts;
            }
        }
        
        if let Ok(val) = env::var("FAILED_ATTEMPT_COOLDOWN") {
            if let Ok(cooldown) = val.parse::<u64>() {
                config.failed_attempt_cooldown = Duration::from_secs(cooldown);
            }
        }
        
        // Backup Settings
        if let Ok(val) = env::var("AUTO_BACKUP") {
            if let Ok(auto_backup) = val.parse() {
                config.auto_backup = auto_backup;
            }
        }
        
        if let Ok(dir) = env::var("BACKUP_DIRECTORY") {
            config.backup_directory = PathBuf::from(dir);
        }
        
        if let Ok(val) = env::var("BACKUP_INTERVAL_DAYS") {
            if let Ok(interval) = val.parse() {
                config.backup_interval_days = interval;
            }
        }
        
        if let Ok(val) = env::var("KEEP_BACKUPS") {
            if let Ok(keep) = val.parse() {
                config.keep_backups = keep;
            }
        }
        
        // Firefox Integration
        if let Ok(paths) = env::var("FIREFOX_PROFILE_PATHS") {
            config.firefox_profile_paths = paths
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from)
                .collect();
        }
        
        // Web Interface
        if let Ok(val) = env::var("WEB_ENABLED") {
            if let Ok(enabled) = val.parse() {
                config.web_enabled = enabled;
            }
        }
        
        if let Ok(val) = env::var("WEB_PORT") {
            if let Ok(port) = val.parse() {
                config.web_port = port;
            }
        }
        
        if let Ok(address) = env::var("WEB_ADDRESS") {
            config.web_address = address;
        }
        
        // Logging
        if let Ok(level) = env::var("LOG_LEVEL") {
            match level.to_lowercase().as_str() {
                "error" => config.log_level = LevelFilter::Error,
                "warn" => config.log_level = LevelFilter::Warn,
                "info" => config.log_level = LevelFilter::Info,
                "debug" => config.log_level = LevelFilter::Debug,
                "trace" => config.log_level = LevelFilter::Trace,
                _ => {}
            }
        }
        
        if let Ok(file) = env::var("LOG_FILE") {
            config.log_file = PathBuf::from(file);
        }
        
        config
    }
    
    // Get the database connection string appropriate for the configured database type
    pub fn get_database_url(&self) -> String {
        match self.database_type {
            DatabaseType::SQLite => {
                if !self.database_url.starts_with("sqlite:") {
                    // If the URL doesn't start with sqlite:, construct a default SQLite URL
                    return "sqlite:./data/securevault.db".to_string();
                }
            },
            DatabaseType::PostgreSQL => {
                if !self.database_url.starts_with("postgres:") && !self.database_url.starts_with("postgresql:") {
                    // If the URL doesn't start with postgres: or postgresql:, construct a default PostgreSQL URL
                    return "postgres://postgres:postgres@localhost/securevault".to_string();
                }
            },
            DatabaseType::Auto => {
                // Keep the URL as is for auto-detection
            }
        }
        
        self.database_url.clone()
    }
    
    // Create directories needed for operation
    pub fn ensure_directories_exist(&self) {
        // Create backup directory if it doesn't exist
        if !self.backup_directory.exists() {
            if let Err(e) = std::fs::create_dir_all(&self.backup_directory) {
                log::warn!("Failed to create backup directory: {}", e);
            }
        }
        
        // Create session directory if specified and it doesn't exist
        if let Some(session_dir) = &self.session_dir {
            if !session_dir.exists() {
                if let Err(e) = std::fs::create_dir_all(session_dir) {
                    log::warn!("Failed to create session directory: {}", e);
                }
            }
        }
        
        // Ensure SQLite database directory exists if using SQLite
        if self.database_type == DatabaseType::SQLite || self.database_type == DatabaseType::Auto {
            if self.database_url.starts_with("sqlite:") {
                let db_path = PathBuf::from(&self.database_url[7..]); // Remove "sqlite:" prefix
                if let Some(parent) = db_path.parent() {
                    if !parent.exists() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            log::warn!("Failed to create SQLite database directory: {}", e);
                        }
                    }
                }
            }
        }
    }
}