// src/system/firejail.rs
use std::path::{Path, PathBuf};
use std::process::{Command, Child, Stdio};
use std::io::{self, Write};
use std::fs;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use crate::privacy::profiles::PrivacyProfile;
use utoipa::ToSchema;

#[derive(Error, Debug)]
pub enum FirejailError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Firejail not installed")]
    NotInstalled,
    
    #[error("Browser not found: {0}")]
    BrowserNotFound(String),
    
    #[error("Failed to create profile: {0}")]
    ProfileCreationError(String),
    
    #[error("Failed to launch browser: {0}")]
    LaunchError(String),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, FirejailError>;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BrowserInfo {
    pub name: String,
    pub binary_path: String,
    pub profile_path: Option<String>,
    pub default_args: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FirejailStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub active_browsers: Vec<ActiveBrowser>,
    pub available_browsers: Vec<BrowserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActiveBrowser {
    pub browser_name: String,
    pub process_id: u32,
    pub started_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LaunchBrowserRequest {
    pub browser: String,
    pub url: Option<String>,
    pub private_mode: Option<bool>,
    pub additional_args: Option<Vec<String>>,
}

pub struct FirejailManager {
    firejail_path: Option<PathBuf>,
    profile_dir: PathBuf,
    active_browsers: Vec<ActiveBrowser>,
}

impl FirejailManager {
    pub fn new(config_dir: PathBuf) -> Self {
        // Find firejail binary
        let firejail_path = Self::find_firejail();
        
        // Create profile directory
        let profile_dir = config_dir.join("firejail");
        if !profile_dir.exists() {
            fs::create_dir_all(&profile_dir).ok();
        }
        
        Self {
            firejail_path,
            profile_dir,
            active_browsers: Vec::new(),
        }
    }
    
    // Check if Firejail is installed
    pub fn is_installed(&self) -> bool {
        self.firejail_path.is_some()
    }
    
    // Get Firejail version
    pub fn get_version(&self) -> Option<String> {
        if let Some(path) = &self.firejail_path {
            if let Ok(output) = Command::new(path)
                .arg("--version")
                .output() {
                if output.status.success() {
                    let version_str = String::from_utf8_lossy(&output.stdout);
                    return Some(version_str.trim().to_string());
                }
            }
        }
        None
    }
    
    // Get Firejail status
    pub fn get_status(&self) -> FirejailStatus {
        let installed = self.is_installed();
        let version = self.get_version();
        
        FirejailStatus {
            installed,
            version,
            active_browsers: self.active_browsers.clone(),
            available_browsers: self.find_available_browsers(),
        }
    }
    
    // Launch a browser in a sandbox
    pub fn launch_browser(&mut self, request: &LaunchBrowserRequest) -> Result<ActiveBrowser> {
        // Check if Firejail is installed
        let firejail_path = match &self.firejail_path {
            Some(path) => path,
            None => return Err(FirejailError::NotInstalled),
        };
        
        // Find the browser
        let browser_info = self.find_browser(&request.browser)?;
        
        // Create a Firejail profile for this browser if needed
        let profile_path = self.ensure_browser_profile(&browser_info)?;
        
        // Build the command
        let mut cmd = Command::new(firejail_path);
        
        // Add standard Firejail arguments
        cmd.arg("--quiet")
           .arg("--profile=".to_string() + profile_path.to_str().unwrap());
        
        // Add browser-specific security flags
        match browser_info.name.to_lowercase().as_str() {
            "firefox" => {
                cmd.arg("--private-dev")
                   .arg("--private-tmp")
                   .arg("--seccomp")
                   .arg("--caps.drop=all")
                   .arg("--nonewprivs");
                
                // Use private browsing if requested
                if request.private_mode.unwrap_or(false) {
                    cmd.arg("--");
                    cmd.arg(&browser_info.binary_path);
                    cmd.arg("--private-window");
                } else {
                    cmd.arg("--");
                    cmd.arg(&browser_info.binary_path);
                }
                
                // Add URL if provided
                if let Some(url) = &request.url {
                    cmd.arg(url);
                }
                
                // Add any additional arguments
                if let Some(args) = &request.additional_args {
                    for arg in args {
                        cmd.arg(arg);
                    }
                }
            },
            "chrome" | "chromium" => {
                cmd.arg("--private-dev")
                   .arg("--private-tmp")
                   .arg("--seccomp")
                   .arg("--caps.drop=all")
                   .arg("--nonewprivs");
                
                cmd.arg("--");
                cmd.arg(&browser_info.binary_path);
                
                // Use incognito mode if requested
                if request.private_mode.unwrap_or(false) {
                    cmd.arg("--incognito");
                }
                
                // Add URL if provided
                if let Some(url) = &request.url {
                    cmd.arg(url);
                }
                
                // Add any additional arguments
                if let Some(args) = &request.additional_args {
                    for arg in args {
                        cmd.arg(arg);
                    }
                }
            },
            _ => {
                // Generic browser handling
                cmd.arg("--private-dev")
                   .arg("--private-tmp")
                   .arg("--seccomp")
                   .arg("--nonewprivs");
                
                cmd.arg("--");
                cmd.arg(&browser_info.binary_path);
                
                // Add URL if provided
                if let Some(url) = &request.url {
                    cmd.arg(url);
                }
                
                // Add any additional arguments
                if let Some(args) = &request.additional_args {
                    for arg in args {
                        cmd.arg(arg);
                    }
                }
            }
        }
        
        // Launch the browser
        let child = cmd.stdout(Stdio::null())
                      .stderr(Stdio::null())
                      .spawn()?;
        
        // Create active browser record
        let active_browser = ActiveBrowser {
            browser_name: browser_info.name.clone(),
            process_id: child.id(),
            started_at: chrono::Utc::now().to_rfc3339(),
        };
        
        // Add to active browsers list
        self.active_browsers.push(active_browser.clone());
        
        Ok(active_browser)
    }
    
    // Find a browser by name
    fn find_browser(&self, name: &str) -> Result<BrowserInfo> {
        let browsers = self.find_available_browsers();
        
        for browser in browsers {
            if browser.name.to_lowercase() == name.to_lowercase() {
                return Ok(browser);
            }
        }
        
        Err(FirejailError::BrowserNotFound(name.to_string()))
    }
    
    // Find all available browsers
    fn find_available_browsers(&self) -> Vec<BrowserInfo> {
        let mut browsers = Vec::new();
        
        // Look for common browsers
        
        // Firefox
        if let Some(path) = Self::find_browser_path("firefox") {
            browsers.push(BrowserInfo {
                name: "Firefox".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        }
        
        // Chrome
        if let Some(path) = Self::find_browser_path("google-chrome") {
            browsers.push(BrowserInfo {
                name: "Chrome".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        } else if let Some(path) = Self::find_browser_path("chrome") {
            browsers.push(BrowserInfo {
                name: "Chrome".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        }
        
        // Chromium
        if let Some(path) = Self::find_browser_path("chromium") {
            browsers.push(BrowserInfo {
                name: "Chromium".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        } else if let Some(path) = Self::find_browser_path("chromium-browser") {
            browsers.push(BrowserInfo {
                name: "Chromium".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        }
        
        // Edge
        if let Some(path) = Self::find_browser_path("microsoft-edge") {
            browsers.push(BrowserInfo {
                name: "Edge".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        }
        
        // Brave
        if let Some(path) = Self::find_browser_path("brave-browser") {
            browsers.push(BrowserInfo {
                name: "Brave".to_string(),
                binary_path: path.to_string_lossy().to_string(),
                profile_path: None,
                default_args: vec![],
            });
        }
        
        browsers
    }
    
    // Create or update a Firejail profile for a browser
    fn ensure_browser_profile(&self, browser_info: &BrowserInfo) -> Result<PathBuf> {
        let profile_name = format!("{}.profile", browser_info.name.to_lowercase());
        let profile_path = self.profile_dir.join(&profile_name);
        
        // Check if profile already exists
        if profile_path.exists() {
            return Ok(profile_path);
        }
        
        // Create profile directory if it doesn't exist
        if !self.profile_dir.exists() {
            fs::create_dir_all(&self.profile_dir)?;
        }
        
        // Get the source profile based on browser type
        let source_profile_path = match browser_info.name.to_lowercase().as_str() {
            "firefox" => PathBuf::from("resources/firejail/firefox.profile"),
            "chrome" | "chromium" | "edge" | "brave" => PathBuf::from("resources/firejail/chromium.profile"),
            _ => PathBuf::from("resources/firejail/generic.profile"),
        };
        
        // Read the source profile
        let profile_content = match fs::read_to_string(&source_profile_path) {
            Ok(content) => content,
            Err(e) => {
                // If we can't read the source profile, create a basic one
                log::warn!("Could not read profile template: {}. Creating basic profile.", e);
                let basic_profile = "# Basic RustVault Firejail profile\ninclude /etc/firejail/default.profile\ncaps.drop all\nseccomp\nnonewprivs\nprivate-dev\nprivate-tmp\n";
                basic_profile.to_string()
            }
        };
        
        // Write the profile
        fs::write(&profile_path, profile_content)?;
        
        Ok(profile_path)
    }
    
    // Find the Firejail binary
    fn find_firejail() -> Option<PathBuf> {
        // Common locations
        let paths = [
            "/usr/bin/firejail",
            "/usr/local/bin/firejail",
            "/bin/firejail",
        ];
        
        for path in &paths {
            let path = PathBuf::from(path);
            if path.exists() {
                return Some(path);
            }
        }
        
        // Try to find using 'which' command
        match Command::new("which")
            .arg("firejail")
            .output() {
            Ok(output) if output.status.success() => {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = PathBuf::from(path_str.trim());
                if path.exists() {
                    return Some(path);
                }
            },
            _ => {}
        }
        
        None
    }
    
    // Find a browser binary
    fn find_browser_path(browser_name: &str) -> Option<PathBuf> {
        // Try to find using 'which' command
        match Command::new("which")
            .arg(browser_name)
            .output() {
            Ok(output) if output.status.success() => {
                let path_str = String::from_utf8_lossy(&output.stdout);
                let path = PathBuf::from(path_str.trim());
                if path.exists() {
                    return Some(path);
                }
            },
            _ => {}
        }
        
        None
    }
    
    // Update active browsers list (check if processes are still running)
    pub fn update_active_browsers(&mut self) {
        let mut still_active = Vec::new();

        for browser in &self.active_browsers {
            if Self::is_process_running(browser.process_id) {
                still_active.push(browser.clone());
            }
        }

        self.active_browsers = still_active;
    }

    
    // Check if a process is still running
    fn is_process_running(pid: u32) -> bool {
        #[cfg(target_family = "unix")]
        {
            use std::fs::File;
            let proc_path = format!("/proc/{}/status", pid);
            File::open(proc_path).is_ok()
        }
        
        #[cfg(target_family = "windows")]
        {
            if let Ok(output) = Command::new("tasklist")
                .arg("/FI")
                .arg(format!("PID eq {}", pid))
                .arg("/NH")
                .output() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains(&format!("{}", pid))
            } else {
                false
            }
        }
    }
    
    // Get installation instructions for the current platform
    pub fn get_installation_instructions() -> String {
        #[cfg(target_os = "linux")]
        {
            // Try to detect the Linux distribution
            if let Ok(output) = Command::new("lsb_release")
                .arg("-si")
                .output() {
                let distro = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
                
                match distro.as_str() {
                    "ubuntu" | "debian" | "linuxmint" => {
                        return "To install Firejail, run the following command in your terminal:\n\nsudo apt-get install firejail".to_string();
                    },
                    "fedora" | "centos" | "rhel" => {
                        return "To install Firejail, run the following command in your terminal:\n\nsudo dnf install firejail".to_string();
                    },
                    "arch" | "manjarolinux" => {
                        return "To install Firejail, run the following command in your terminal:\n\nsudo pacman -S firejail".to_string();
                    },
                    "opensuse" => {
                        return "To install Firejail, run the following command in your terminal:\n\nsudo zypper install firejail".to_string();
                    },
                    _ => {}
                }
            }
            
            // Generic Linux instructions
            "To install Firejail on your Linux distribution, please use your package manager to install the 'firejail' package.\n\nFor example:\n- Debian/Ubuntu: sudo apt-get install firejail\n- Fedora: sudo dnf install firejail\n- Arch Linux: sudo pacman -S firejail\n\nAlternatively, you can download it from the official website: https://firejail.wordpress.com/".to_string()
        }
        
        #[cfg(target_os = "macos")]
        {
            "Firejail is primarily designed for Linux and is not officially supported on macOS.\n\nFor sandbox functionality on macOS, consider using the built-in App Sandbox or other macOS-specific security features.".to_string()
        }
        
        #[cfg(target_os = "windows")]
        {
            "Firejail is designed for Linux and is not available on Windows.\n\nFor sandbox functionality on Windows, consider using Windows Sandbox, which is built into Windows 10 Pro and Enterprise editions.".to_string()
        }
    }
}