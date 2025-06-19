//src/privacy/browsers/common.rs

use std::path::PathBuf;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum BrowserError {
    IoError(io::Error),
    ProfileNotFound,
    ProfileCorrupted,
    Other(String),
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrowserError::IoError(e) => write!(f, "I/O error: {}", e),
            BrowserError::ProfileNotFound => write!(f, "Browser profile not found"),
            BrowserError::ProfileCorrupted => write!(f, "Browser profile is corrupted"),
            BrowserError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for BrowserError {}

impl From<io::Error> for BrowserError {
    fn from(err: io::Error) -> Self {
        BrowserError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, BrowserError>;

// Common function to find browser profile directories
pub fn find_profiles_dir(base_path: &PathBuf) -> Result<PathBuf> {
    if base_path.exists() {
        Ok(base_path.clone())
    } else {
        Err(BrowserError::ProfileNotFound)
    }
}

// Common function to backup a browser file before modifying
pub fn backup_file(file_path: &PathBuf) -> Result<()> {
    if file_path.exists() {
        let backup_path = file_path.with_extension("bak");
        fs::copy(file_path, backup_path)?;
    }
    Ok(())
}

// Common function to read lines from a browser configuration file
pub fn read_lines(file_path: &PathBuf) -> Result<Vec<String>> {
    let file = fs::File::open(file_path)?;
    let reader = BufReader::new(file);
    let lines = reader.lines().collect::<io::Result<Vec<String>>>()?;
    Ok(lines)
}

// Common function to write lines to a browser configuration file
pub fn write_lines(file_path: &PathBuf, lines: &[String]) -> Result<()> {
    let mut file = fs::File::create(file_path)?;
    for line in lines {
        writeln!(file, "{}", line)?;
    }
    Ok(())
}