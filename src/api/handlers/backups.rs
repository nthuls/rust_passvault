// src/api/handlers/backups.rs - Fixed version
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use std::path::PathBuf;
use crate::core::vault::Vault;
// use crate::db::Database;
use crate::backups::BackupManager;
use crate::api::types::{
    BackupListResponse, SuccessResponse, CreateBackupRequest, RestoreBackupRequest
};
use crate::api::utils::extract_token;
use log::{info, error};
use hex;
use rustix::path::Arg;
use utoipa::ToSchema;

/// List all backups
///
/// Returns a list of all available backups.
#[utoipa::path(
    get,
    path = "/backups",
    tag = "Backups",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of backups", body = BackupListResponse),
        (status = 401, description = "Unauthorized", body = BackupListResponse),
        (status = 500, description = "Server error", body = BackupListResponse)
    )
)]
pub async fn list_backups(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    let (_token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(BackupListResponse {
                success: false,
                backups: vec![],
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    let backup_dir = crate::utils::get_app_config_dir()
        .map(|d| d.join("backups"))
        .unwrap_or_else(|| PathBuf::from("./backups"));
    let backup_manager = BackupManager::new(backup_dir);

    match backup_manager.get_all_backups() {
        Ok(backups) => {
            let api_backups = backups.into_iter()
                .map(|b| crate::api::types::BackupMetadata {
                    id: b.id.to_string(),
                    filename: b.filename.to_string(),
                    created_at: b.created_at.to_string(),
                    description: b.description,
                    size_bytes: b.size_bytes,
                    password_count: b.password_count,
                    category_count: b.category_count,
                })
                .collect();

            HttpResponse::Ok().json(BackupListResponse {
                success: true,
                backups: api_backups,
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to get backups: {}", e);
            HttpResponse::InternalServerError().json(BackupListResponse {
                success: false,
                backups: vec![],
                error: Some(e.to_string()),
            })
        }
    }
}

/// Create a backup
///
/// Creates a new backup of the vault.
#[utoipa::path(
    post,
    path = "/backups",
    tag = "Backups",
    security(
        ("bearer_auth" = [])
    ),
    request_body = CreateBackupRequest,
    responses(
        (status = 200, description = "Backup created", body = SuccessResponse),
        (status = 400, description = "Invalid input", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 500, description = "Server error", body = SuccessResponse)
    )
)]
pub async fn create_backup(
    vault: web::Data<Arc<Vault>>,
    _req: HttpRequest,
    backup_req: web::Json<CreateBackupRequest>,
) -> impl Responder {
    // Extract token from the request
    let (_token, session_id) = match extract_token(&_req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    // Get master key
    let master_key = match vault.auth_manager.get_master_key(&session_id) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };

    // Get database reference
    let db = vault.get_db_ref();

    // Determine backup directory
    let backup_dir = match crate::utils::get_app_config_dir() {
        Some(mut path) => {
            path.push("backups");
            path
        },
        None => {
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Failed to determine backup directory".to_string()),
            });
        }
    };

    // Create backup manager
    let backup_manager = BackupManager::new(backup_dir);

    // Get the backup password (use provided or fallback to master_key hex)
    let backup_password_string = backup_req
        .backup_password
        .clone()
        .unwrap_or_else(|| hex::encode(&master_key));

    // Create backup
    match backup_manager
        .create_backup(
            &db,
            &master_key,
            backup_req.description.clone(), // Option<String>
            Some(backup_password_string.as_str()),
        )
        .await
    {
        Ok(metadata) => {
            info!("Backup created: {:?}", metadata.id); // or display full metadata if Display is implemented

            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some(format!("Backup created successfully with ID: {:?}", metadata.id)),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to create backup: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create backup: {}", e)),
            })
        }
    }
}


/// Restore a backup
///
/// Restores the vault from a backup.
#[utoipa::path(
    post,
    path = "/backups/{id}/restore",
    tag = "Backups",
    params(
        ("id" = String, Path, description = "Backup ID")
    ),
    request_body = RestoreBackupRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Backup restored", body = SuccessResponse),
        (status = 400, description = "Restore failed", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 500, description = "Server error", body = SuccessResponse)
    )
)]
pub async fn restore_backup(
    vault: web::Data<Arc<Vault>>,
    _req: HttpRequest,
    restore_req: web::Json<RestoreBackupRequest>,
) -> impl Responder {
    // Extract token
    let (_token, session_id) = match extract_token(&_req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    // Get master key
    let master_key = match vault.auth_manager.get_master_key(&session_id) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };

    // Get database
    let db = vault.get_db_ref();

    // Determine backup path
    let backup_dir = match crate::utils::get_app_config_dir() {
        Some(mut path) => {
            path.push("backups");
            path
        },
        None => {
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Could not resolve backup directory".to_string()),
            });
        }
    };

    let backup_manager = BackupManager::new(backup_dir);

    // Get backup password (provided or fallback)
    let backup_password = restore_req
        .backup_password
        .clone()
        .unwrap_or_else(|| hex::encode(&master_key));

    // Restore backup (by ID)
    match backup_manager
        .restore_backup(
            &restore_req.id,
            &db,
            &master_key,
            Some(backup_password.as_str()),
        )
        .await
    {
        Ok(_) => {
            info!("Backup successfully restored");
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Backup restored successfully".to_string()),
                error: None,
            })
        }
        Err(e) => {
            let (mut status, message) = match e.to_string().as_str() {
                s if s.contains("decryption") =>
                    (HttpResponse::BadRequest(), "Invalid backup password".to_string()),
                s if s.contains("not found") =>
                    (HttpResponse::NotFound(), format!("Backup not found: {}", e)),
                _ =>
                    (HttpResponse::InternalServerError(), format!("Failed to restore backup: {}", e)),
            };

            error!("Restore failed: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Delete a backup
///
/// Deletes a backup from the system.
#[utoipa::path(
    delete,
    path = "/backups/{id}",
    tag = "Backups",
    params(
        ("id" = String, Path, description = "Backup ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Backup deleted", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 404, description = "Backup not found", body = SuccessResponse)
    )
)]
pub async fn delete_backup(
    vault: web::Data<Arc<Vault>>,
    _req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    // Extract token from the request
    let (_token, _) = match extract_token(&_req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    // Get backup ID from path
    let backup_id = path.into_inner();

    // Get backup directory
    let backup_dir = match crate::utils::get_app_config_dir() {
        Some(mut path) => {
            path.push("backups");
            path
        },
        None => {
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Could not determine backup directory".to_string()),
            });
        }
    };

    // Create backup manager
    let backup_manager = BackupManager::new(backup_dir);

    // Delete the backup
    match backup_manager.delete_backup(&backup_id) {
        Ok(_) => {
            info!("Backup deleted: {}", backup_id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Backup deleted successfully".to_string()),
                error: None,
            })
        }
        Err(e) => {
            let (mut status, message) = match e.to_string().as_str() {
                s if s.contains("not found") =>
                    (HttpResponse::NotFound(), format!("Backup not found: {}", e)),
                _ =>
                    (HttpResponse::InternalServerError(), format!("Failed to delete backup: {}", e)),
            };

            error!("Failed to delete backup: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Get backup details
///
/// Returns detailed information about a specific backup.
#[utoipa::path(
    get,
    path = "/backups/{id}",
    tag = "Backups",
    params(
        ("id" = String, Path, description = "Backup ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Backup details", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 404, description = "Backup not found", body = SuccessResponse)
    )
)]
pub async fn get_backup_details(
    vault: web::Data<Arc<Vault>>,
    _req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    // Extract token from the request
    let (_token, _) = match extract_token(&_req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    // Get backup ID from path
    let backup_id = path.into_inner();

    // Get backup directory
    let backup_dir = match crate::utils::get_app_config_dir() {
        Some(mut path) => {
            path.push("backups");
            path
        }
        None => {
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Could not determine backup directory".to_string()),
            });
        }
    };

    // Create backup manager
    let backup_manager = BackupManager::new(backup_dir);

    // Get backup details
    match backup_manager.get_backup_details(&backup_id) {
        Ok(backup) => {
            let api_backup = crate::api::types::BackupMetadata {
                id: backup.id.to_string(),
                filename: backup.filename.to_string_lossy().to_string(),
                created_at: backup.created_at.to_string(),
                description: backup.description,
                size_bytes: backup.size_bytes,
                password_count: backup.password_count,
                category_count: backup.category_count,
            };

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "backup": api_backup,
                "error": null
            }))
        }
        Err(e) => {
            let is_not_found = e.to_string().contains("not found");
            let message = if is_not_found {
                format!("Backup not found: {}", backup_id)
            } else {
                format!("Failed to get backup details: {}", e)
            };

            error!("Failed to get backup details: {}", message);

            let mut status = if is_not_found {
                HttpResponse::NotFound()
            } else {
                HttpResponse::InternalServerError()
            };

            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}
