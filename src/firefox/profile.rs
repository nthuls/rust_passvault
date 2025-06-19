// src/firefox/profile.rs
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{BufRead, BufReader};
use dirs;

// Firefox profile detector
pub struct FirefoxProfiler {
    profile_paths: Vec<PathBuf>,
}

impl FirefoxProfiler {
    // Create a new Firefox profiler
    pub fn new() -> Self {
        let mut profile_paths = Vec::new();
        
        // Get default profile locations based on OS
        if let Some(paths) = Self::get_default_profile_paths() {
            profile_paths.extend(paths);
        }
        
        Self { profile_paths }
    }
    
    // Get Firefox profile paths based on operating system
    fn get_default_profile_paths() -> Option<Vec<PathBuf>> {
        let mut paths = Vec::new();
        
        if cfg!(target_os = "windows") {
            // Windows paths
            if let Some(appdata) = dirs::config_dir() {
                paths.push(appdata.join("Mozilla").join("Firefox"));
            }
        } else if cfg!(target_os = "macos") {
            // macOS paths
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join("Library/Application Support/Firefox"));
            }
        } else {
            // Linux/Unix paths
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join(".mozilla/firefox"));
            }
        }
        
        if paths.is_empty() {
            None
        } else {
            Some(paths)
        }
    }
    
    // Find Firefox profiles
    pub fn find_profiles(&self) -> Vec<(String, PathBuf)> {
        let mut profiles = Vec::new();
        
        for base_path in &self.profile_paths {
            if !base_path.exists() {
                continue;
            }
            
            let profiles_ini = base_path.join("profiles.ini");
            if !profiles_ini.exists() {
                continue;
            }
            
            // Simple parsing of the profiles.ini file
            if let Ok(file) = fs::File::open(&profiles_ini) {
                let reader = BufReader::new(file);
                
                let mut in_profile_section = false;
                let mut profile_name = String::new();
                let mut profile_path = String::new();
                let mut is_relative = false;
                
                for line in reader.lines() {
                    if let Ok(line) = line {
                        let line = line.trim();
                        
                        // Check for profile section
                        if line.starts_with("[Profile") && line.ends_with("]") {
                            in_profile_section = true;
                            profile_name.clear();
                            profile_path.clear();
                            is_relative = false;
                        } 
                        // Process profile section
                        else if in_profile_section {
                            if line.starts_with("Name=") {
                                profile_name = line["Name=".len()..].to_string();
                            } else if line.starts_with("Path=") {
                                profile_path = line["Path=".len()..].to_string();
                            } else if line.starts_with("IsRelative=") {
                                is_relative = &line["IsRelative=".len()..] == "1";
                            } else if line.starts_with("[") {
                                // New section, process the profile we just read
                                if !profile_name.is_empty() && !profile_path.is_empty() {
                                    let full_path = if is_relative {
                                        base_path.join(&profile_path)
                                    } else {
                                        PathBuf::from(&profile_path)
                                    };
                                    
                                    if full_path.exists() {
                                        profiles.push((profile_name.clone(), full_path));
                                    }
                                }
                                
                                in_profile_section = line.starts_with("[Profile");
                                if in_profile_section {
                                    profile_name.clear();
                                    profile_path.clear();
                                    is_relative = false;
                                }
                            }
                        }
                    }
                }
                
                // Process the last profile if we were in a profile section
                if in_profile_section && !profile_name.is_empty() && !profile_path.is_empty() {
                    let full_path = if is_relative {
                        base_path.join(&profile_path)
                    } else {
                        PathBuf::from(&profile_path)
                    };
                    
                    if full_path.exists() {
                        profiles.push((profile_name.clone(), full_path));
                    }
                }
            }
        }
        
        profiles
    }
    
    // Check if a path contains Firefox credentials
    pub fn has_credentials(&self, profile_path: &Path) -> bool {
        // Check for logins.json (newer Firefox)
        let logins_json = profile_path.join("logins.json");
        if logins_json.exists() {
            return true;
        }
        
        // Check for signons.sqlite (older Firefox)
        let signons_sqlite = profile_path.join("signons.sqlite");
        if signons_sqlite.exists() {
            return true;
        }
        
        false
    }
}