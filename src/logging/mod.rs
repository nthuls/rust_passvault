// src/logging/mod.rs
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Log rotation error: {0}")]
    RotationError(String),
}

pub type Result<T> = std::result::Result<T, LoggingError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARNING"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub component: String,
    pub message: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub error_details: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LogFilter {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub level: Option<LogLevel>,
    pub component: Option<String>,
    pub search_term: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub struct Logger {
    log_dir: PathBuf,
    current_log_file: PathBuf,
    max_log_size: u64,        // Maximum size of a log file before rotation (in bytes)
    max_log_files: usize,     // Maximum number of log files to keep
}

impl Logger {
    pub fn new(log_dir: PathBuf) -> Result<Self> {
        if !log_dir.exists() {
            fs::create_dir_all(&log_dir)?;
        }
        
        let current_log_file = log_dir.join("rustvault.log");
        
        // Create the log file if it doesn't exist
        if !current_log_file.exists() {
            File::create(&current_log_file)?;
        }
        
        Ok(Self {
            log_dir,
            current_log_file,
            max_log_size: 10 * 1024 * 1024,  // 10 MB default
            max_log_files: 5,                // Keep 5 log files by default
        })
    }
    
    // Log a new entry
    pub fn log(&self, level: LogLevel, component: &str, message: &str, 
               user_id: Option<&str>, session_id: Option<&str>, 
               error_details: Option<&str>) -> Result<()> {
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            component: component.to_string(),
            message: message.to_string(),
            user_id: user_id.map(String::from),
            session_id: session_id.map(String::from),
            error_details: error_details.map(String::from),
        };
        
        // Check if log rotation is needed
        self.check_rotation()?;
        
        // Write the log entry
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&self.current_log_file)?;
        
        let log_line = format!("{} [{}] [{}] {}{}{}\n",
            entry.timestamp.to_rfc3339(),
            entry.level,
            entry.component,
            entry.message,
            entry.user_id.map_or(String::new(), |id| format!(" [User: {}]", id)),
            entry.error_details.map_or(String::new(), |err| format!(" [Error: {}]", err))
        );
        
        file.write_all(log_line.as_bytes())?;
        
        Ok(())
    }
    
    // Get logs with filtering
    pub fn get_logs(&self, filter: &LogFilter) -> Result<Vec<LogEntry>> {
        let mut entries = Vec::new();
        
        // Read the log file
        let content = fs::read_to_string(&self.current_log_file)?;
        
        for line in content.lines() {
            // Parse the log line
            if let Some(entry) = self.parse_log_line(line) {
                // Apply filters
                if self.entry_matches_filter(&entry, filter) {
                    entries.push(entry);
                }
            }
        }
        
        // Apply limit and offset
        let offset = filter.offset.unwrap_or(0);
        let limit = filter.limit.unwrap_or(usize::MAX);
        
        let start = offset.min(entries.len());
        let end = (offset + limit).min(entries.len());
        
        Ok(entries[start..end].to_vec())
    }
    
    // Check if log rotation is needed
    fn check_rotation(&self) -> Result<()> {
        let metadata = fs::metadata(&self.current_log_file)?;
        
        if metadata.len() > self.max_log_size {
            self.rotate_logs()?;
        }
        
        Ok(())
    }
    
    // Rotate log files
    fn rotate_logs(&self) -> Result<()> {
        // Get current timestamp for the rotated log file name
        let now = Utc::now();
        let timestamp = now.format("%Y%m%d%H%M%S");
        
        let rotated_log_file = self.log_dir.join(format!("rustvault-{}.log", timestamp));
        
        // Rename the current log file
        fs::rename(&self.current_log_file, &rotated_log_file)?;
        
        // Create a new current log file
        File::create(&self.current_log_file)?;
        
        // Clean up old log files if necessary
        self.cleanup_old_logs()?;
        
        Ok(())
    }
    
    // Clean up old log files, keeping only the most recent ones
    fn cleanup_old_logs(&self) -> Result<()> {
        let mut log_files = Vec::new();
        
        for entry in fs::read_dir(&self.log_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && 
               path.extension().map_or(false, |ext| ext == "log") &&
               path != self.current_log_file {
                log_files.push(path);
            }
        }
        
        // Sort by modification time (newest first)
        log_files.sort_by(|a, b| {
            let a_modified = fs::metadata(a).and_then(|m| m.modified()).unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
            let b_modified = fs::metadata(b).and_then(|m| m.modified()).unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH);
            b_modified.cmp(&a_modified)
        });
        
        // Remove excess log files
        if log_files.len() > self.max_log_files - 1 {
            for file in log_files.iter().skip(self.max_log_files - 1) {
                fs::remove_file(file)?;
            }
        }
        
        Ok(())
    }
    
    // Parse a log line into a LogEntry
    fn parse_log_line(&self, line: &str) -> Option<LogEntry> {
        // Example format: 2023-06-15T12:34:56Z [INFO] [Auth] User logged in [User: user123] [Error: details]
        
        // Split by first space to get timestamp
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return None;
        }
        
        let timestamp_str = parts[0];
        let rest = parts[1];
        
        // Parse timestamp
        let timestamp = match timestamp_str.parse::<DateTime<Utc>>() {
            Ok(ts) => ts,
            Err(_) => return None,
        };
        
        // Parse level
        if !rest.starts_with('[') {
            return None;
        }
        
        let level_end = rest.find(']')?;
        let level_str = &rest[1..level_end];
        
        let level = match level_str {
            "DEBUG" => LogLevel::Debug,
            "INFO" => LogLevel::Info,
            "WARNING" => LogLevel::Warning,
            "ERROR" => LogLevel::Error,
            "CRITICAL" => LogLevel::Critical,
            _ => return None,
        };
        
        // Parse component
        let component_start = rest[level_end+1..].find('[')?;
        let component_text = &rest[level_end+1+component_start..];
        let component_end = component_text.find(']')?;
        let component = component_text[1..component_end].to_string();
        
        // Parse message (everything between component and optional user/error)
        let message_start = level_end + 1 + component_start + component_end + 1;
        
        let mut message_end = rest.len();
        let mut user_id = None;
        let mut error_details = None;
        
        // Check for user ID
        if let Some(user_start) = rest.find("[User: ") {
            message_end = user_start;
            let user_text = &rest[user_start..];
            if let Some(user_end) = user_text.find(']') {
                user_id = Some(user_text[7..user_end].to_string());
            }
        }
        
        // Check for error details
        if let Some(error_start) = rest.find("[Error: ") {
            if message_end == rest.len() || error_start < message_end {
                message_end = error_start;
            }
            let error_text = &rest[error_start..];
            if let Some(error_end) = error_text.find(']') {
                error_details = Some(error_text[8..error_end].to_string());
            }
        }
        
        let message = rest[message_start..message_end].trim().to_string();
        
        Some(LogEntry {
            timestamp,
            level,
            component,
            message,
            user_id,
            session_id: None, // We don't include session_id in the log line format
            error_details,
        })
    }
    
    // Check if a log entry matches the filter
    fn entry_matches_filter(&self, entry: &LogEntry, filter: &LogFilter) -> bool {
        // Check start date
        if let Some(start_date) = filter.start_date {
            if entry.timestamp < start_date {
                return false;
            }
        }
        
        // Check end date
        if let Some(end_date) = filter.end_date {
            if entry.timestamp > end_date {
                return false;
            }
        }
        
        // Check level
        if let Some(level) = filter.level {
            match level {
                LogLevel::Debug => {}, // All levels pass
                LogLevel::Info => if entry.level == LogLevel::Debug { return false; },
                LogLevel::Warning => if entry.level == LogLevel::Debug || entry.level == LogLevel::Info { return false; },
                LogLevel::Error => if entry.level != LogLevel::Error && entry.level != LogLevel::Critical { return false; },
                LogLevel::Critical => if entry.level != LogLevel::Critical { return false; },
            }
        }
        
        // Check component
        if let Some(component) = &filter.component {
            if !entry.component.contains(component) {
                return false;
            }
        }
        
        // Check search term
        if let Some(term) = &filter.search_term {
            if !entry.message.contains(term) &&
               !entry.component.contains(term) &&
               !entry.user_id.as_ref().map_or(false, |id| id.contains(term)) &&
               !entry.error_details.as_ref().map_or(false, |err| err.contains(term)) {
                return false;
            }
        }
        
        true
    }
}