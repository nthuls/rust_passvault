// src/utils/format.rs
use chrono::{DateTime, Utc};

// Format a duration for display
pub fn format_time_ago(time: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(time);
    
    let seconds = duration.num_seconds();
    
    if seconds < 60 {
        format!("{} seconds ago", seconds)
    } else if seconds < 3600 {
        format!("{} minutes ago", duration.num_minutes())
    } else if seconds < 86400 {
        format!("{} hours ago", duration.num_hours())
    } else if seconds < 2592000 {
        format!("{} days ago", duration.num_days())
    } else if seconds < 31536000 {
        format!("{} months ago", duration.num_days() / 30)
    } else {
        format!("{} years ago", duration.num_days() / 365)
    }
}

// Truncate a string if it's too long
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[0..max_len-3])
    }
}

// Generate a secure salt
pub fn generate_salt() -> String {
    use rand::{thread_rng, RngCore};
    use base64::{engine::general_purpose, Engine as _};
    
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    
    general_purpose::STANDARD.encode(salt)
}