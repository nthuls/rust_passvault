// src/api/handlers/export.rs - FIXED VERSION

use actix_web::{web, HttpRequest, HttpResponse, Responder, http::header};
use std::sync::Arc;
use tempfile::NamedTempFile;
use crate::core::vault::Vault;
use crate::importers::CsvImporter;
use crate::api::types::{ExportRequest, SuccessResponse};
use crate::api::utils::{extract_token, extract_master_key};
use log::{info, error, debug};
use crate::crypto;

/// Options handler for export endpoints
pub async fn export_options() -> impl Responder {
    HttpResponse::Ok()
        .append_header(("Access-Control-Allow-Origin", "*"))
        .append_header(("Access-Control-Allow-Methods", "GET, OPTIONS"))
        .append_header(("Access-Control-Allow-Headers", "Content-Type, Authorization"))
        .finish()
}

/// Export passwords to CSV
///
/// Exports all passwords to a CSV file.
#[utoipa::path(
    get,
    path = "/export",
    tag = "Export",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("include_passwords" = Option<bool>, Query, description = "Include actual password values (default: false)"),
        ("include_notes" = Option<bool>, Query, description = "Include notes (default: true)")
    ),
    responses(
        (status = 200, description = "CSV export success", content_type = "text/csv"),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 500, description = "Internal server error", body = SuccessResponse)
    )
)]
pub async fn export_csv(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    query: web::Query<ExportRequest>,
) -> impl Responder {
    // Log for debugging
    debug!("🔍 export_csv called with query params: {:?}", query);
    
    // Extract token
    let (token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            error!("❌ Authentication error in export_csv: {}", e);
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Authentication error: {}", e)),
                });
        }
    };
    
    // Get master key
    let master_key = match extract_master_key(&req) {
        Ok(key) => key,
        Err(e) => {
            error!("❌ Failed to get master key: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to get master key: {}", e)),
                });
        }
    };
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create a temporary file for the CSV
    let temp_file = match NamedTempFile::new() {
        Ok(file) => file,
        Err(e) => {
            error!("❌ Failed to create temporary file: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to create temporary file: {}", e)),
                });
        }
    };
    
    // Create CSV exporter
    let exporter = CsvImporter::new();
    
    // Export to CSV
    match exporter.export(
        temp_file.path(),
        &db,
        &master_key,
        ',', // Default delimiter
        true, // Include headers
    ).await {
        Ok(count) => {
            info!("✅ Successfully exported {} passwords to CSV", count);
            
            // Read the file content
            let csv_content = match std::fs::read_to_string(temp_file.path()) {
                Ok(content) => content,
                Err(e) => {
                    error!("❌ Failed to read exported CSV: {}", e);
                    return HttpResponse::InternalServerError()
                        .append_header(("Access-Control-Allow-Origin", "*"))
                        .json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some(format!("Failed to read exported CSV: {}", e)),
                        });
                }
            };
            
            // Return the CSV file as a download
            HttpResponse::Ok()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .append_header((header::CONTENT_TYPE, "text/csv"))
                .append_header((
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"rustvault_export.csv\"",
                ))
                .body(csv_content)
        },
        Err(e) => {
            error!("❌ Failed to export to CSV: {}", e);
            HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to export to CSV: {}", e)),
                })
        }
    }
}

/// Export vault
///
/// Exports the entire vault as an encrypted file.
#[utoipa::path(
    get,
    path = "/export/vault",
    tag = "Export",
    security(
        ("bearer_auth" = [])
    ),
    params(
        ("include_passwords" = Option<bool>, Query, description = "Include actual password values (default: false)"),
        ("include_notes" = Option<bool>, Query, description = "Include notes (default: true)"),
        ("password" = Option<String>, Query, description = "Password to encrypt the export (if different from master password)")
    ),
    responses(
        (status = 200, description = "Vault exported successfully", content_type = "application/octet-stream"),
        (status = 401, description = "Unauthorized", body = SuccessResponse),
        (status = 500, description = "Server error", body = SuccessResponse)
    )
)]
pub async fn export_vault(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    query: web::Query<ExportRequest>,
) -> impl Responder {
    // Log for debugging
    debug!("🔍 export_vault called with query params: {:?}", query);
    
    // Extract token and get master key
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            error!("❌ Authentication error in export_vault: {}", e);
            return HttpResponse::Unauthorized()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
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
            error!("❌ Failed to get master key: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to get master key: {}", e)),
                });
        }
    };
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Get all passwords
    let passwords = match db.get_all_passwords().await {
        Ok(passwords) => passwords,
        Err(e) => {
            error!("❌ Failed to get passwords: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to retrieve passwords: {}", e)),
                });
        }
    };
    
    // Get all categories
    let categories = match db.get_all_categories().await {
        Ok(categories) => categories,
        Err(e) => {
            error!("❌ Failed to get categories: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to retrieve categories: {}", e)),
                });
        }
    };
    
    // Determine if we should include passwords
    let include_passwords = query.include_passwords.unwrap_or(false);
    
    // Determine if we should include notes
    let include_notes = query.include_notes.unwrap_or(true);
    
    // Create export data structure
    let mut export_data = serde_json::json!({
        "metadata": {
            "version": env!("CARGO_PKG_VERSION"),
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "password_count": passwords.len(),
            "category_count": categories.len(),
        },
        "categories": categories,
        "passwords": []
    });
    
    // Process passwords for export
    let password_entries: Vec<serde_json::Value> = passwords.iter().map(|password_entry| {
        let mut entry = serde_json::json!({
            "id": password_entry.id.to_string(),
            "site": password_entry.site,
            "username": password_entry.username,
            "created_at": password_entry.created_at,
            "updated_at": password_entry.updated_at,
            "categories": password_entry.categories,
        });
        
        // Include password if requested
        if include_passwords {
            // Decrypt the password
            match crypto::decrypt_password(&master_key, &password_entry.password) {
                Ok(decrypted) => {
                    entry["password"] = serde_json::Value::String(decrypted);
                },
                Err(e) => {
                    error!("❌ Failed to decrypt password: {}", e);
                    // Still include the entry, just without the password
                }
            }
        }
        
        // Include notes if requested and available
        if include_notes && password_entry.notes.is_some() {
            entry["notes"] = serde_json::Value::String(password_entry.notes.clone().unwrap_or_default());
        }
        
        entry
    }).collect();
    
    // Add passwords to export data
    export_data["passwords"] = serde_json::Value::Array(password_entries);
    
    // Serialize the export data
    let export_json = match serde_json::to_string_pretty(&export_data) {
        Ok(json) => json,
        Err(e) => {
            error!("❌ Failed to serialize export data: {}", e);
            return HttpResponse::InternalServerError()
                .append_header(("Access-Control-Allow-Origin", "*"))
                .json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Failed to serialize export data: {}", e)),
                });
        }
    };
    
    // Use master key for encryption if no password provided
    if query.password.is_none() {
        // Encrypt the export data using the master key directly
        match crypto::encrypt_data(&master_key, export_json.as_bytes()) {
            Ok(encrypted_data) => {
                // Generate a filename for the export
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let filename = format!("rustvault_export_{}.vault", timestamp);
                
                // Return the encrypted file
                return HttpResponse::Ok()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .content_type("application/octet-stream")
                    .append_header((
                        actix_web::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ))
                    .body(encrypted_data);
            },
            Err(e) => {
                error!("❌ Failed to encrypt export data: {}", e);
                return HttpResponse::InternalServerError()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to encrypt export data: {}", e)),
                    });
            }
        }
    } else {
        // Use custom password for encryption
        let password = query.password.as_ref().unwrap();
        
        // Log but sanitize the password for security
        debug!("🔑 Using custom password for export encryption (length: {})", password.len());
        
        // Sanitize the password to remove special characters
        let sanitized_password = password.replace('+', "").replace('/', "").replace('=', "");
        
        // FIX: Use a simpler key derivation for export encryption to avoid salt issues
        let encryption_key = match crypto::derive_key_from_password(&sanitized_password, "EXPORT_SALT") {
            Ok(key) => key,
            Err(e) => {
                error!("❌ Failed to derive key from password: {}", e);
                return HttpResponse::InternalServerError()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to derive encryption key: {}", e)),
                    });
            }
        };
        
        // Encrypt the export data
        match crypto::encrypt_data(&encryption_key, export_json.as_bytes()) {
            Ok(encrypted_data) => {
                // Generate a filename for the export
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let filename = format!("rustvault_export_{}.vault", timestamp);
                
                // Return the encrypted file
                return HttpResponse::Ok()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .content_type("application/octet-stream")
                    .append_header((
                        actix_web::http::header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{}\"", filename),
                    ))
                    .body(encrypted_data);
            },
            Err(e) => {
                error!("❌ Failed to encrypt export data: {}", e);
                return HttpResponse::InternalServerError()
                    .append_header(("Access-Control-Allow-Origin", "*"))
                    .json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to encrypt export data: {}", e)),
                    });
            }
        }
    }
}