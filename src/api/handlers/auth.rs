// src/api/handlers/auth.rs - Rewritten for better error handling and CORS compatibility

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use crate::core::vault::Vault;
use crate::core::auth::{AuthManager, AuthError};
use crate::api::types::{
    UnlockRequest, TokenResponse, StatusResponse, 
    SuccessResponse, ChangePasswordRequest
};
use log::{info, warn, error};
use utoipa::path;

/// Unlock the vault with the master password
///
/// Returns a JWT token for subsequent authenticated requests.
#[utoipa::path(
    post,
    path = "/auth/unlock",
    tag = "Authentication",
    request_body = UnlockRequest,
    responses(
        (status = 200, description = "Vault unlocked successfully", body = TokenResponse),
        (status = 401, description = "Invalid credentials", body = TokenResponse),
        (status = 500, description = "Internal server error", body = TokenResponse)
    )
)]
pub async fn unlock_vault(
    vault: web::Data<Arc<Vault>>,
    req: web::Json<UnlockRequest>,
) -> impl Responder {
    println!("🔥 ENTERED unlock_vault"); // CLI print, bypasses log
    info!("Attempting to unlock vault");
    
    // Add more logging to help debug issues
    info!("Received unlock request with password length: {}", req.password.len());
    
    match vault.unlock(&req.password).await {
        Ok(token) => {
            info!("Vault unlocked successfully, token length: {}", token.len());
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
                .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
                .json(TokenResponse {
                    success: true,
                    token: Some(token),
                    error: None,
                })
        },
        Err(e) => {
            match e {
                AuthError::InvalidCredentials => {
                    warn!("Invalid credentials used to unlock vault");
                    HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(TokenResponse {
                            success: false,
                            token: None,
                            error: Some("Invalid master password".to_string()),
                        })
                },
                AuthError::SessionExpired => {
                    warn!("Session expired during unlock attempt");
                    HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(TokenResponse {
                            success: false,
                            token: None,
                            error: Some("Session expired".to_string()),
                        })
                },
                _ => {
                    error!("Error unlocking vault: {}", e);
                    HttpResponse::InternalServerError()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(TokenResponse {
                            success: false,
                            token: None,
                            error: Some(format!("Failed to unlock vault: {}", e)),
                        })
                }
            }
        }
    }
}

/// Handle OPTIONS requests for the unlock endpoint
pub async fn unlock_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// Check if the current session is valid
///
/// Returns the authentication status of the current token.
#[utoipa::path(
    get,
    path = "/auth/status",
    tag = "Authentication",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Authentication status", body = StatusResponse)
    )
)]
pub async fn check_status(
    req: HttpRequest,
) -> impl Responder {
    // Create auth manager
    let auth_manager = AuthManager::new();
    
    // Check if the request has a valid token
    let auth_header = req.headers().get("Authorization");
    
    if let Some(header) = auth_header {
        if let Ok(header_str) = header.to_str() {
            if header_str.starts_with("Bearer ") {
                let token = &header_str[7..];
                
                // Validate the token
                match auth_manager.validate_token(token) {
                    Ok(_) => {
                        return HttpResponse::Ok()
                            .append_header(("Access-Control-Allow-Origin", "*"))
                            .json(StatusResponse {
                                success: true,
                                authenticated: true,
                            });
                    },
                    Err(e) => {
                        info!("Invalid token in status check: {}", e);
                    }
                }
            }
        }
    }
    
    // Not authenticated
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .json(StatusResponse {
            success: true,
            authenticated: false,
        })
}

/// Handle OPTIONS requests for the status endpoint
pub async fn status_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "GET, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// Logout (invalidate the current session)
///
/// Invalidates the provided token, effectively logging the user out.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Authentication",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Logout successful", body = SuccessResponse),
        (status = 400, description = "Invalid request", body = SuccessResponse),
        (status = 500, description = "Internal server error", body = SuccessResponse)
    )
)]
pub async fn logout(
    req: HttpRequest,
    vault: web::Data<Arc<Vault>>,
) -> impl Responder {
    // Get the token from the Authorization header
    let auth_header = req.headers().get("Authorization");
    
    if let Some(header) = auth_header {
        if let Ok(header_str) = header.to_str() {
            if header_str.starts_with("Bearer ") {
                let token = &header_str[7..];
                
                // Logout using the token
                match vault.logout(token) {
                    Ok(_) => {
                        info!("User logged out successfully");
                        return HttpResponse::Ok()
                            .append_header(("Access-Control-Allow-Origin", "*"))
                            .json(SuccessResponse {
                                success: true,
                                message: Some("Logged out successfully".to_string()),
                                error: None,
                            });
                    },
                    Err(e) => {
                        error!("Failed to logout: {}", e);
                        return HttpResponse::InternalServerError()
                            .append_header(("Access-Control-Allow-Origin", "*"))
                            .json(SuccessResponse {
                                success: false,
                                message: None,
                                error: Some(format!("Failed to logout: {}", e)),
                            });
                    }
                }
            }
        }
    }
    
    warn!("Invalid authorization header in logout request");
    HttpResponse::BadRequest()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Invalid or missing authorization header".to_string()),
        })
}

/// Handle OPTIONS requests for the logout endpoint
pub async fn logout_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// Change the master password
///
/// Changes the master password for the vault. This will re-encrypt all stored passwords.
#[utoipa::path(
    post,
    path = "/auth/change-password",
    tag = "Authentication",
    request_body = ChangePasswordRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Password changed successfully", body = SuccessResponse),
        (status = 400, description = "Invalid request", body = SuccessResponse),
        (status = 401, description = "Unauthorized or invalid current password", body = SuccessResponse),
        (status = 500, description = "Internal server error", body = SuccessResponse)
    )
)]
pub async fn change_password(
    req: web::Json<ChangePasswordRequest>,
    vault: web::Data<Arc<Vault>>,
    http_req: HttpRequest,
) -> impl Responder {
    // First validate the current token
    let auth_header = http_req.headers().get("Authorization");
    
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    return HttpResponse::BadRequest()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                return HttpResponse::BadRequest()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Validate current password by trying to unlock the vault
    match vault.unlock(&req.current_password).await {
        Ok(_) => {
            // Password is correct, proceed with change
            match vault.update_master_password(token, &req.current_password, &req.new_password).await {
                Ok(_) => {
                    info!("Master password changed successfully");
                    HttpResponse::Ok()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: true,
                            message: Some("Master password changed successfully".to_string()),
                            error: None,
                        })
                },
                Err(e) => {
                    error!("Failed to change master password: {}", e);
                    HttpResponse::InternalServerError()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some(format!("Failed to change master password: {}", e)),
                        })
                }
            }
        },
        Err(e) => {
            match e {
                AuthError::InvalidCredentials => {
                    warn!("Invalid current password in change password request");
                    HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid current password".to_string()),
                        })
                },
                _ => {
                    error!("Error validating current password: {}", e);
                    HttpResponse::InternalServerError()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some(format!("Error validating current password: {}", e)),
                        })
                }
            }
        }
    }
}

/// Handle OPTIONS requests for the change-password endpoint
pub async fn change_password_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "POST, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// Get the raw token from the Authorization header
pub fn get_raw_token_from_header(req: &HttpRequest) -> Result<String, String> {
    // Get the Authorization header
    let auth_header = match req.headers().get("Authorization") {
        Some(h) => h,
        None => return Err("Missing Authorization header".to_string()),
    };
    
    // Convert to string
    let header_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return Err("Invalid Authorization header".to_string()),
    };
    
    // Check for Bearer format
    if !header_str.starts_with("Bearer ") {
        return Err("Invalid Authorization header format".to_string());
    }
    
    // Extract the token
    Ok(header_str[7..].to_string())
}
