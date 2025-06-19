// src/api/handlers/passwords.rs
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use uuid::Uuid;
use crate::core::vault::Vault;
use crate::crypto;
use crate::api::types::{
    PasswordListResponse, PasswordEntry, 
    AddPasswordRequest, UpdatePasswordRequest, SuccessResponse,
    CountResponse
};
use log::{info, error, debug};
use actix_web::HttpMessage;
use chrono::DateTime;

pub async fn passwords_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// List all passwords
///
/// Returns a list of all passwords in the vault (without the actual password values).
#[utoipa::path(
    get,
    path = "/passwords",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List all passwords", body = PasswordListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn list_passwords(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    debug!("🔍 list_passwords called");
    
    // Extract the token directly from the Authorization header
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    debug!("❌ Invalid authorization header format");
                    return HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(PasswordListResponse {
                            success: false,
                            passwords: vec![],
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                debug!("❌ Invalid authorization header");
                return HttpResponse::Unauthorized()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(PasswordListResponse {
                        success: false,
                        passwords: vec![],
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            debug!("❌ Missing authorization header");
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(PasswordListResponse {
                    success: false,
                    passwords: vec![],
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Log the token for debugging (first few chars only for security)
    let token_preview = token.chars().take(10).collect::<String>() + "...";
    debug!("🔑 Using token: {}", token_preview);
    
    // Get all passwords
    match vault.get_all_passwords(&token).await {
        Ok(passwords) => {
            debug!("✅ Successfully retrieved {} passwords", passwords.len());
            // Convert to API format (without decrypting passwords)
            let password_entries: Vec<PasswordEntry> = passwords
                .into_iter()
                .map(|p| PasswordEntry {
                    id: p.id.to_string(),
                    site: p.site,
                    username: p.username,
                    password: None, // Don't include password in listing
                    notes: p.notes,
                    categories: p.categories,
                    created_at: p.created_at.to_rfc3339(),
                    updated_at: p.updated_at.to_rfc3339(),
                    strength: None, // We don't have the password, so we can't calculate strength
                })
                .collect();
            
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(PasswordListResponse {
                    success: true,
                    passwords: password_entries,
                    error: None,
                })
        },
        Err(e) => {
            error!("Failed to get passwords: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(PasswordListResponse {
                    success: false,
                    passwords: vec![],
                    error: Some(format!("Failed to get passwords: {}", e)),
                })
        }
    }
}

/// Get a specific password
///
/// Returns a specific password including the decrypted password value.
#[utoipa::path(
    get,
    path = "/passwords/{id}",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Password UUID")
    ),
    responses(
        (status = 200, description = "Password found", body = PasswordEntry),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Password not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_password(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    debug!("🔍 get_password called");
    
    // Extract the token directly from the Authorization header
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    debug!("❌ Invalid authorization header format");
                    return HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                debug!("❌ Invalid authorization header");
                return HttpResponse::Unauthorized()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            debug!("❌ Missing authorization header");
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Parse UUID
    let id = match Uuid::parse_str(&path) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Invalid UUID format".to_string()),
                });
        }
    };
    
    // Get password by ID
    match vault.get_password_by_id(&token, id).await {
        Ok(password) => {
            // Decrypt the password
            let decrypted_password = match vault.decrypt_password(&token, &password.password).await {
                Ok(pwd) => pwd,
                Err(e) => {
                    error!("Failed to decrypt password: {}", e);
                    return HttpResponse::InternalServerError()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some(format!("Failed to decrypt password: {}", e)),
                        });
                }
            };
            
            // Calculate password strength
            let strength = crypto::analyze_password_strength(&decrypted_password);
            
            // Convert to API format
            let password_entry = PasswordEntry {
                id: password.id.to_string(),
                site: password.site,
                username: password.username,
                password: Some(decrypted_password),
                notes: password.notes,
                categories: password.categories,
                created_at: password.created_at.to_rfc3339(),
                updated_at: password.updated_at.to_rfc3339(),
                strength: Some(strength),
            };
            
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(password_entry)
        },
        Err(e) => {
            // Check if it's a "not found" error
            if format!("{}", e).contains("not found") {
                return HttpResponse::NotFound()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Password with ID {} not found", id)),
                    });
            }
            
            error!("Failed to get password: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to get password: {}", e)),
                })
        }
    }
}

/// Add a new password
///
/// Creates a new password entry in the vault.
#[utoipa::path(
    post,
    path = "/passwords",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    request_body = AddPasswordRequest,
    responses(
        (status = 201, description = "Password added successfully", body = SuccessResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn add_password(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    password_req: web::Json<AddPasswordRequest>,
) -> impl Responder {
    debug!("🔍 add_password called");
    
    // Extract the token directly from the Authorization header
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    debug!("❌ Invalid authorization header format");
                    return HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                debug!("❌ Invalid authorization header");
                return HttpResponse::Unauthorized()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            debug!("❌ Missing authorization header");
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Validate input
    if password_req.site.trim().is_empty() {
        return HttpResponse::BadRequest()
            .append_header(("Access-Control-Allow-Origin", "*"))
            .json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Site cannot be empty".to_string()),
            });
    }
    
    if password_req.username.trim().is_empty() {
        return HttpResponse::BadRequest()
            .append_header(("Access-Control-Allow-Origin", "*"))
            .json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Username cannot be empty".to_string()),
            });
    }
    
    if password_req.password.trim().is_empty() {
        return HttpResponse::BadRequest()
            .append_header(("Access-Control-Allow-Origin", "*"))
            .json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Password cannot be empty".to_string()),
            });
    }
    
    // Get categories (or empty array if none provided)
    let categories = password_req.categories.clone().unwrap_or_else(Vec::new);
    
    // Add password
    match vault.add_password(
        &token,
        &password_req.site,
        &password_req.username,
        &password_req.password,
        password_req.notes.as_deref(),
        &categories,
    ).await {
        Ok(id) => {
            info!("Password added successfully with ID: {}", id);
            HttpResponse::Created()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: true,
                    message: Some(format!("Password added successfully with ID: {}", id)),
                    error: None,
                })
        },
        Err(e) => {
            error!("Failed to add password: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to add password: {}", e)),
                })
        }
    }
}

/// Update a password
///
/// Updates an existing password entry in the vault.
#[utoipa::path(
    put,
    path = "/passwords/{id}",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Password UUID")
    ),
    request_body = UpdatePasswordRequest,
    responses(
        (status = 200, description = "Password updated successfully", body = SuccessResponse),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Password not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn update_password(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    path: web::Path<String>,
    password_req: web::Json<UpdatePasswordRequest>,
) -> impl Responder {
    debug!("🔍 update_password called");
    
    // Extract the token directly from the Authorization header
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    debug!("❌ Invalid authorization header format");
                    return HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                debug!("❌ Invalid authorization header");
                return HttpResponse::Unauthorized()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            debug!("❌ Missing authorization header");
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Parse UUID
    let id = match Uuid::parse_str(&path) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Invalid UUID format".to_string()),
                });
        }
    };
    
    // Check if at least one field is being updated
    // Check if at least one field is being updated
    if password_req.site.trim().is_empty()
        && password_req.username.trim().is_empty()
        && password_req.password.trim().is_empty()
        && password_req.notes.as_ref().map(|n| n.trim().is_empty()).unwrap_or(true)
        && password_req.categories.as_ref().map(|c| c.is_empty()).unwrap_or(true)
    {
        return HttpResponse::BadRequest()
            .append_header(("Access-Control-Allow-Origin", "*"))
            .json(SuccessResponse {
                success: false,
                message: None,
                error: Some("No fields to update".to_string()),
            });
    }
    
    // Check if the password exists first
    match vault.get_password_by_id(&token, id).await {
        Ok(_) => {
            // Password exists, proceed with update
        },
        Err(e) => {
            // Check if it's a "not found" error
            if format!("{}", e).contains("not found") {
                return HttpResponse::NotFound()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Password with ID {} not found", id)),
                    });
            }
            
            error!("Failed to check if password exists: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to check if password exists: {}", e)),
                });
        }
    }
    
    // Update password
    match vault.update_password(
        &token,
        id,
        Some(password_req.site.as_str()),
        Some(password_req.username.as_str()),
        Some(password_req.password.as_str()),
        password_req.notes.as_deref(),
        password_req.categories.as_deref(),
    ).await {
        Ok(_) => {
            info!("Password with ID {} updated successfully", id);
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: true,
                    message: Some("Password updated successfully".to_string()),
                    error: None,
                })
        },
        Err(e) => {
            error!("Failed to update password: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to update password: {}", e)),
                })
        }
    }
}

/// Delete a password
///
/// Deletes a password entry from the vault.
#[utoipa::path(
    delete,
    path = "/passwords/{id}",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("id" = String, Path, description = "Password UUID")
    ),
    responses(
        (status = 200, description = "Password deleted successfully", body = SuccessResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Password not found"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn delete_password(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    debug!("🔍 delete_password called");
    
    // Extract the token directly from the Authorization header
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(header) => {
            if let Ok(header_str) = header.to_str() {
                if header_str.starts_with("Bearer ") {
                    &header_str[7..]
                } else {
                    debug!("❌ Invalid authorization header format");
                    return HttpResponse::Unauthorized()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Invalid authorization header format".to_string()),
                        });
                }
            } else {
                debug!("❌ Invalid authorization header");
                return HttpResponse::Unauthorized()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some("Invalid authorization header".to_string()),
                    });
            }
        },
        None => {
            debug!("❌ Missing authorization header");
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Missing authorization header".to_string()),
                });
        }
    };
    
    // Parse UUID
    let id = match Uuid::parse_str(&path) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some("Invalid UUID format".to_string()),
                });
        }
    };
    
    // Delete password
    match vault.delete_password(&token, id).await {
        Ok(_) => {
            info!("Password with ID {} deleted successfully", id);
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: true,
                    message: Some("Password deleted successfully".to_string()),
                    error: None,
                })
        },
        Err(e) => {
            // Check if it's a "not found" error
            if format!("{}", e).contains("not found") {
                return HttpResponse::NotFound()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Password with ID {} not found", id)),
                    });
            }
            
            error!("Failed to delete password: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to delete password: {}", e)),
                })
        }
    }
}

/// Count all stored passwords
///
/// Returns the number of stored password entries in the vault.
#[utoipa::path(
    get,
    path = "/passwords/count",
    tag = "Passwords",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Returns the total number of stored passwords", body = CountResponse),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn count_passwords(
    vault: web::Data<Arc<Vault>>
) -> impl Responder {
    match vault.count_passwords().await {
        Ok(count) => HttpResponse::Ok().json(CountResponse {
            success: true,
            count: count as i64, // Convert usize to i64
        }),
        Err(e) => {
            error!("Failed to get password count: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}