// src/api/utils.rs

use actix_web::{HttpRequest, HttpMessage};
use actix_web::error::ErrorUnauthorized;
use crate::core::auth::AuthManager;
use log::{debug, warn};

/// Extract and validate the token from an HTTP request
///
/// Returns the token and session ID if validation is successful.
pub fn extract_token(req: &HttpRequest) -> Result<(String, String), actix_web::Error> {
    debug!("🔍 extract_token called, checking for token");
    
    // First try to get from extensions (set by middleware)
    if let (Some(token), Some(session_id)) = (
        req.extensions().get::<String>(),
        req.extensions().get::<String>()
    ) {
        debug!("✅ Using token from request extensions, session_id: {}", session_id);
        return Ok((token.clone(), session_id.clone()));
    } else {
        debug!("⚠️ Token or session_id not found in extensions, trying header extraction");
    }
    
    // If not in extensions, try to extract from header
    let auth_header = req.headers().get("Authorization")
        .ok_or_else(|| {
            warn!("❌ Missing authorization header");
            ErrorUnauthorized("Missing authorization header")
        })?;
    
    let header_str = auth_header.to_str()
        .map_err(|e| {
            warn!("❌ Invalid authorization header: {}", e);
            ErrorUnauthorized("Invalid authorization header")
        })?;
    
    if !header_str.starts_with("Bearer ") {
        warn!("❌ Invalid authorization header format: {}", header_str);
        return Err(ErrorUnauthorized("Invalid authorization header format"));
    }
    
    let token = header_str[7..].to_string();
    debug!("📝 Extracted token from header: {}", token.chars().take(10).collect::<String>() + "...");
    
    // Validate the token
    let auth_manager = AuthManager::new();
    debug!("🔐 Validating token with AuthManager");
    let session_id = match auth_manager.validate_token(&token) {
        Ok(sid) => {
            debug!("✅ Token successfully validated, session_id: {}", sid);
            sid
        },
        Err(e) => {
            warn!("❌ Token validation failed: {}", e);
            return Err(ErrorUnauthorized(format!("Invalid token: {}", e)));
        }
    };
    
    Ok((token, session_id))
}

/// Extract the master key from request extensions
///
/// If the master key is not in extensions, get it from the session ID.
pub fn extract_master_key(req: &HttpRequest) -> Result<Vec<u8>, actix_web::Error> {
    // Try to get from extensions first (set by middleware)
    if let Some(master_key) = req.extensions().get::<Vec<u8>>() {
        return Ok(master_key.clone());
    }
    
    // If not in extensions, get the session ID and then the master key
    let (_, session_id) = extract_token(req)?;
    
    let auth_manager = AuthManager::new();
    let master_key = auth_manager.get_master_key(&session_id)
        .map_err(|e| {
            warn!("Failed to get master key: {}", e);
            ErrorUnauthorized(format!("Failed to get master key: {}", e))
        })?;
    
    Ok(master_key)
}