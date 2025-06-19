// Update src/privacy/fingerprint/mod.rs
use serde::{Serialize, Deserialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct FingerprintSettings {
    pub canvas_protection: bool,
    pub webgl_protection: bool,
    pub audio_protection: bool,
    pub font_protection: bool,
    pub hardware_protection: bool,
    // Add new settings
    pub timezone_protection: bool,
    pub language_protection: bool,
    pub screen_size_protection: bool,
    pub user_agent_protection: bool,
    pub plugin_protection: bool,
    pub accept_header_protection: bool,
}

impl FingerprintSettings {
    // Check if any fingerprinting protection is active
    pub fn is_active(&self) -> bool {
        self.canvas_protection || 
        self.webgl_protection || 
        self.audio_protection || 
        self.font_protection || 
        self.hardware_protection ||
        self.timezone_protection ||
        self.language_protection ||
        self.screen_size_protection ||
        self.user_agent_protection ||
        self.plugin_protection ||
        self.accept_header_protection
    }
    
    // Get protection level string
    pub fn get_protection_level(&self) -> String {
        let active_count = self.count_active_protections();
        let total_count = self.count_total_protections();
        
        if active_count == total_count {
            "High".to_string()
        } else if active_count > total_count / 2 {
            "Medium".to_string()
        } else if active_count > 0 {
            "Low".to_string()
        } else {
            "None".to_string()
        }
    }
    
    // Count active protections
    fn count_active_protections(&self) -> usize {
        let mut count = 0;
        if self.canvas_protection { count += 1; }
        if self.webgl_protection { count += 1; }
        if self.audio_protection { count += 1; }
        if self.font_protection { count += 1; }
        if self.hardware_protection { count += 1; }
        if self.timezone_protection { count += 1; }
        if self.language_protection { count += 1; }
        if self.screen_size_protection { count += 1; }
        if self.user_agent_protection { count += 1; }
        if self.plugin_protection { count += 1; }
        if self.accept_header_protection { count += 1; }
        count
    }
    
    // Count total available protections
    fn count_total_protections(&self) -> usize {
        11 // Update this if more protections are added
    }
}