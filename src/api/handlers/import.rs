// src/api/handlers/import.rs

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use actix_multipart::Multipart;
use std::sync::Arc;
use std::path::PathBuf;
use std::io::Write;
// use std::fs;
use futures::{StreamExt, TryStreamExt};
use tempfile::NamedTempFile;
use crate::core::vault::Vault;
use crate::importers::{FirefoxImporter, CsvImporter};
use crate::api::types::{
    FirefoxProfileListResponse, FirefoxProfileEntry,
    ImportFirefoxRequest, ImportChromeRequest, ImportEdgeRequest,
    ImportResponse
};
use crate::api::utils::{extract_token, extract_master_key};
use log::{info, error, debug};
use std::collections::HashMap;
use crate::importers::ChromeImporter;
use crate::importers::EdgeImporter;
use crate::crypto;
use sqlx::types::Uuid;

/// List available Firefox profiles
///
/// Returns a list of Firefox profiles that can be imported.
#[utoipa::path(
    get,
    path = "/import/firefox/profiles",
    tag = "Import",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of available Firefox profiles", body = FirefoxProfileListResponse),
        (status = 401, description = "Unauthorized", body = FirefoxProfileListResponse),
        (status = 500, description = "Server error", body = FirefoxProfileListResponse)
    )
)]
pub async fn list_firefox_profiles(
    req: HttpRequest,
) -> impl Responder {
    // Extract token (just for authentication)
    let (_, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(FirefoxProfileListResponse {
                success: false,
                profiles: vec![],
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Create Firefox importer
    let importer = FirefoxImporter::new();
    
    // Get Firefox profiles
    let profiles = importer.list_profiles();
    
    // Convert to API format
    let profile_entries: Vec<FirefoxProfileEntry> = profiles
        .iter()
        .map(|(name, path)| FirefoxProfileEntry {
            name: name.clone(),
            path: path.to_string_lossy().to_string(),
        })
        .collect();
    
    if profile_entries.is_empty() {
        return HttpResponse::Ok().json(FirefoxProfileListResponse {
            success: true,
            profiles: vec![],
            error: Some("No Firefox profiles found".to_string()),
        });
    }
    
    HttpResponse::Ok().json(FirefoxProfileListResponse {
        success: true,
        profiles: profile_entries,
        error: None,
    })
}

/// Import passwords from Firefox
///
/// Imports passwords from a Firefox profile.
#[utoipa::path(
    post,
    path = "/import/firefox",
    tag = "Import",
    request_body = ImportFirefoxRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Passwords imported successfully from Firefox", body = ImportResponse),
        (status = 400, description = "Invalid profile or request", body = ImportResponse),
        (status = 401, description = "Unauthorized", body = ImportResponse),
        (status = 500, description = "Internal server error", body = ImportResponse)
    )
)]
pub async fn import_firefox(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    import_req: web::Json<ImportFirefoxRequest>,
) -> impl Responder {
    // Extract token
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get master key
    let master_key = match extract_master_key(&req) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };
    
    // Create Firefox importer
    let importer = FirefoxImporter::new();
    
    // Get profile path
    let profile_path = match &import_req.profile_path {
        Some(path) => PathBuf::from(path),
        None => {
            // Use default profile if none specified
            let profiles = importer.list_profiles();
            
            if profiles.is_empty() {
                return HttpResponse::BadRequest().json(ImportResponse {
                    success: false,
                    count: 0,
                    added_count: Some(0),
                    updated_count: Some(0),
                    message: None,
                    error: Some("No Firefox profiles found".to_string()),
                });
            }
            
            // Use the first profile
            profiles[0].1.clone()
        }
    };
    
    // Check if profile exists
    if !profile_path.exists() {
        return HttpResponse::BadRequest().json(ImportResponse {
            success: false,
            count: 0,
            added_count: Some(0),
            updated_count: Some(0),
            message: None,
            error: Some(format!("Profile path not found: {}", profile_path.display())),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Determine if we should update existing passwords
    let update_existing = import_req.update_existing.unwrap_or(false);
    
    // Import the credentials
    match importer.import_credentials(
        profile_path.clone(),
        import_req.master_password.as_deref(),
        &db,
        &master_key,
        import_req.category.as_deref(),
        update_existing,
    ).await {
        Ok((added, updated)) => {
            let total = added + updated;
            info!("Successfully imported {} passwords from Firefox ({} new, {} updated)", 
                 total, added, updated);
            
            HttpResponse::Ok().json(ImportResponse {
                success: true,
                count: total,
                added_count: Some(added),
                updated_count: Some(updated),
                message: Some(format!("Successfully imported {} passwords from Firefox ({} new, {} updated)",
                                    total, added, updated)),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to import Firefox credentials: {}", e);
            HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to import Firefox credentials: {}", e)),
            })
        }
    }
}

/// Import passwords from Chrome
///
/// Imports passwords from a Chrome profile.
#[utoipa::path(
    post,
    path = "/import/chrome",
    tag = "Import",
    request_body = ImportChromeRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Passwords imported successfully", body = ImportResponse),
        (status = 400, description = "Invalid request", body = ImportResponse),
        (status = 401, description = "Unauthorized", body = ImportResponse),
        (status = 500, description = "Server error", body = ImportResponse)
    )
)]
pub async fn import_chrome(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    import_req: web::Json<ImportChromeRequest>,
) -> impl Responder {
    // Extract token and get master key
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get master key
    let master_key = match extract_master_key(&req) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };
    
    // Create Chrome importer
    let importer = ChromeImporter::new();
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Determine if we should update existing passwords
    let update_existing = import_req.update_existing.unwrap_or(false);
    
    // Import the credentials
    match importer.import_passwords(
        &db,
        import_req.profile_path.as_deref(),
        &master_key,
        import_req.category.as_deref(),
        Some(update_existing), // Convert bool to Option<bool>
    ).await {
        Ok((added, updated)) => {
            let total = added + updated;
            info!("Successfully imported {} passwords from Chrome ({} new, {} updated)", 
                 total, added, updated);
                 
            HttpResponse::Ok().json(ImportResponse {
                success: true,
                count: total,
                added_count: Some(added),
                updated_count: Some(updated),
                message: Some(format!("Successfully imported {} passwords from Chrome ({} new, {} updated)",
                                     total, added, updated)),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to import Chrome credentials: {}", e);
            HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to import Chrome credentials: {}", e)),
            })
        }
    }
}

/// Import passwords from Edge
///
/// Imports passwords from an Edge profile.
#[utoipa::path(
    post,
    path = "/import/edge",
    tag = "Import",
    request_body = ImportEdgeRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Passwords imported successfully", body = ImportResponse),
        (status = 400, description = "Invalid request", body = ImportResponse),
        (status = 401, description = "Unauthorized", body = ImportResponse),
        (status = 500, description = "Server error", body = ImportResponse)
    )
)]
pub async fn import_edge(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    import_req: web::Json<ImportEdgeRequest>,
) -> impl Responder {
    // Extract token and get master key
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get master key
    let master_key = match extract_master_key(&req) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };
    
    // Create Edge importer
    let importer = EdgeImporter::new();
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Determine if we should update existing passwords
    let update_existing = import_req.update_existing.unwrap_or(false);
    
    // Import the credentials
    match importer.import_passwords(
        &db,
        import_req.profile_path.as_deref(),
        &master_key,
        import_req.category.as_deref(),
        Some(update_existing), // Convert bool to Option<bool>
    ).await {
        Ok((added, updated)) => {
            let total = added + updated;
            info!("Successfully imported {} passwords from Edge ({} new, {} updated)", 
                 total, added, updated);
                 
            HttpResponse::Ok().json(ImportResponse {
                success: true,
                count: total,
                added_count: Some(added),
                updated_count: Some(updated),
                message: Some(format!("Successfully imported {} passwords from Edge ({} new, {} updated)",
                                     total, added, updated)),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to import Edge credentials: {}", e);
            HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to import Edge credentials: {}", e)),
            })
        }
    }
}

/// Import passwords from CSV
///
/// Imports passwords from a CSV file.
#[utoipa::path(
    post,
    path = "/import/csv",
    tag = "Import",
    request_body(
        content = ImportCSVRequest,
        content_type = "multipart/form-data"
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "CSV import successful", body = ImportResponse),
        (status = 400, description = "Invalid form data or upload", body = ImportResponse),
        (status = 401, description = "Unauthorized", body = ImportResponse),
        (status = 500, description = "Server error", body = ImportResponse)
    )
)]
pub async fn import_csv(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    mut payload: Multipart,
) -> impl Responder {
    // Extract token
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get master key
    let master_key = match extract_master_key(&req) {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get master key: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };
    
    // Create a temporary file to store the uploaded CSV
    let mut temp_file = match NamedTempFile::new() {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to create temporary file: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to create temporary file: {}", e)),
            });
        }
    };
    
    // Default values
    let mut delimiter = ',';
    let mut has_header = true;
    let mut category: Option<String> = None;
    let mut update_existing = false;
    
    // Process the multipart form
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let field_name = match content_disposition.get_name() {
            Some(name) => name,
            None => continue,
        };
        
        match field_name {
            "file" => {
                // Save the file content
                while let Some(chunk) = field.next().await {
                    let data = match chunk {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Failed to read file chunk: {}", e);
                            return HttpResponse::InternalServerError().json(ImportResponse {
                                success: false,
                                count: 0,
                                added_count: Some(0),
                                updated_count: Some(0),
                                message: None,
                                error: Some(format!("Failed to read file chunk: {}", e)),
                            });
                        }
                    };
                    if let Err(e) = temp_file.write_all(&data) {
                        error!("Failed to write to temporary file: {}", e);
                        return HttpResponse::InternalServerError().json(ImportResponse {
                            success: false,
                            count: 0,
                            added_count: Some(0),
                            updated_count: Some(0),
                            message: None,
                            error: Some(format!("Failed to write to temporary file: {}", e)),
                        });
                    }
                }
            },
            "delimiter" => {
                // Get the delimiter
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk.unwrap_or_default());
                }
                let delim_str = String::from_utf8_lossy(&data);
                if !delim_str.is_empty() {
                    delimiter = delim_str.chars().next().unwrap_or(',');
                }
            },
            "has_header" => {
                // Get the has_header flag
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk.unwrap_or_default());
                }
                let header_str = String::from_utf8_lossy(&data);
                has_header = header_str.trim() != "false";
            },
            "category" => {
                // Get the category
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk.unwrap_or_default());
                }
                let cat_str = String::from_utf8_lossy(&data);
                if !cat_str.trim().is_empty() {
                    category = Some(cat_str.to_string());
                }
            },
            "update_existing" => {
                // Get the update_existing flag
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk.unwrap_or_default());
                }
                let update_str = String::from_utf8_lossy(&data);
                update_existing = update_str.trim() == "true";
            },
            _ => {
                // Ignore unknown fields
            }
        }
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create CSV importer
    let importer = CsvImporter::new();
    
    // Import from CSV
    match importer.import(
        temp_file.path(),
        &db,
        &master_key,
        delimiter,
        has_header,
        category.as_deref(),
        update_existing,
    ).await {
        Ok((added, updated)) => {
            let total = added + updated;
            info!("Successfully imported {} passwords from CSV ({} new, {} updated)", 
                 total, added, updated);
                 
            HttpResponse::Ok().json(ImportResponse {
                success: true,
                count: total,
                added_count: Some(added),
                updated_count: Some(updated),
                message: Some(format!("Successfully imported {} passwords from CSV ({} new, {} updated)",
                                     total, added, updated)),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to import CSV: {}", e);
            HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to import CSV: {}", e)),
            })
        }
    }
}

/// Import vault
///
/// Imports a previously exported vault file.
#[utoipa::path(
    post,
    path = "/import/vault",
    tag = "Import",
    request_body(
        content = ImportVaultRequest,
        content_type = "multipart/form-data"
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Passwords imported successfully", body = ImportResponse),
        (status = 500, description = "Server error", body = ImportResponse)
    )
)]
pub async fn import_vault(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    mut payload: Multipart,
) -> impl Responder {
    // Extract token and get master key
    let (token, session_id) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
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
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Failed to get master key: {}", e)),
            });
        }
    };
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Variables to store file content and password
    let mut file_data: Option<Vec<u8>> = None;
    let mut import_password: Option<String> = None;
    let mut update_existing = false;
    
    // Process multipart form
    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let name = match content_disposition.get_name() {
            Some(name) => name,
            None => continue,
        };
        
        match name {
            "file" => {
                // Read file content
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    let bytes = match chunk {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("Error reading file chunk: {}", e);
                            return HttpResponse::BadRequest().json(ImportResponse {
                                success: false,
                                count: 0,
                                added_count: Some(0),
                                updated_count: Some(0),
                                message: None,
                                error: Some("Failed to read uploaded file".to_string()),
                            });
                        }
                    };
                    data.extend_from_slice(&bytes);
                }
                file_data = Some(data);
            },
            "password" => {
                // Read password field
                let mut password = String::new();
                while let Some(chunk) = field.next().await {
                    let bytes = match chunk {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("Error reading password field: {}", e);
                            return HttpResponse::BadRequest().json(ImportResponse {
                                success: false,
                                count: 0,
                                added_count: Some(0),
                                updated_count: Some(0),
                                message: None,
                                error: Some("Failed to read password field".to_string()),
                            });
                        }
                    };
                    password.extend(bytes.iter().map(|&b| b as char));
                }
                if !password.is_empty() {
                    import_password = Some(password);
                }
            },
            "update_existing" => {
                // Get the update_existing flag
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    data.extend_from_slice(&chunk.unwrap_or_default());
                }
                let update_str = String::from_utf8_lossy(&data);
                update_existing = update_str.trim() == "true";
            },
            _ => {
                // Ignore unknown fields
            }
        }
    }
    
    // Ensure we have file data
    let file_content = match file_data {
        Some(data) => data,
        None => {
            return HttpResponse::BadRequest().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some("No file uploaded".to_string()),
            });
        }
    };
    
    // Decrypt the file content
    // Use provided password or master key for decryption
    let decryption_key = if let Some(password) = import_password {
        // Derive a key from the provided password
        match crypto::derive_key_from_password(&password, "EXPORT") {
            Ok(key) => key,
            Err(e) => {
                error!("Failed to derive key: {}", e);
                return HttpResponse::InternalServerError().json(ImportResponse {
                    success: false,
                    count: 0,
                    added_count: Some(0),
                    updated_count: Some(0),
                    message: None,
                    error: Some(format!("Failed to derive decryption key: {}", e)),
                });
            }
        }
    } else {
        // Use master key
        master_key.clone()
    };
    
    // Decrypt the import data
    let decrypted_data = match crypto::decrypt_data(&decryption_key, &file_content) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decrypt import data: {}", e);
            return HttpResponse::BadRequest().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some("Failed to decrypt file. Incorrect password or corrupted file.".to_string()),
            });
        }
    };
    
    // Parse the decrypted JSON
    let import_data: serde_json::Value = match serde_json::from_slice(&decrypted_data) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to parse import data: {}", e);
            return HttpResponse::BadRequest().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some("Invalid vault file format".to_string()),
            });
        }
    };
    
    // Begin a database transaction
    let mut tx = match db.begin_transaction().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {}", e);
            return HttpResponse::InternalServerError().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some(format!("Database error: {}", e)),
            });
        }
    };
    
    // Import categories first
    let mut category_map: HashMap<String, Uuid> = HashMap::new();
    let categories = match import_data["categories"].as_array() {
        Some(categories) => categories,
        None => {
            error!("Categories not found in import data");
            return HttpResponse::BadRequest().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some("Invalid vault file: categories not found".to_string()),
            });
        }
    };
    
    // Process each category
    for category in categories {
        let name = match category["name"].as_str() {
            Some(name) => name,
            None => continue,
        };
        
        // Try to get or create the category
        match db.get_or_create_category(name).await {
            Ok(id) => {
                category_map.insert(name.to_string(), id);
            },
            Err(e) => {
                error!("Failed to create category {}: {}", name, e);
                // Continue with other categories
            }
        }
    }
    
    // Now import passwords
    let passwords = match import_data["passwords"].as_array() {
        Some(passwords) => passwords,
        None => {
            error!("Passwords not found in import data");
            return HttpResponse::BadRequest().json(ImportResponse {
                success: false,
                count: 0,
                added_count: Some(0),
                updated_count: Some(0),
                message: None,
                error: Some("Invalid vault file: passwords not found".to_string()),
            });
        }
    };
    
    // Track how many passwords were imported
    let mut added_count = 0;
    let mut updated_count = 0;
    
    // Process each password
    for password_data in passwords {
        // Extract required fields
        let site = match password_data["site"].as_str() {
            Some(site) => site,
            None => continue, // Skip this password
        };
        
        let username = match password_data["username"].as_str() {
            Some(username) => username,
            None => continue, // Skip this password
        };
        
        // Password might not be included in export
        let password = password_data["password"].as_str();
        if password.is_none() && !password_data.as_object().unwrap().contains_key("password") {
            // Skip passwords without password value (they were likely exported with include_passwords=false)
            continue;
        }
        // Notes are optional
       let notes = password_data["notes"].as_str();
       
       // Get categories for this password
       let password_categories = match password_data["categories"].as_array() {
           Some(cats) => {
               cats.iter()
                   .filter_map(|c| c.as_str())
                   .map(|s| s.to_string())
                   .collect::<Vec<String>>()
           },
           None => Vec::new(),
       };
       
       // Encrypt the password if present
       let encrypted_password = if let Some(pwd) = password {
           match crypto::encrypt_password(&master_key, pwd) {
               Ok(enc) => enc,
               Err(e) => {
                   error!("Failed to encrypt password: {}", e);
                   continue; // Skip this password
               }
           }
       } else {
           // Generate a placeholder if password not included
           let placeholder = "[PASSWORD NOT INCLUDED IN EXPORT]";
           match crypto::encrypt_password(&master_key, placeholder) {
               Ok(enc) => enc,
               Err(e) => {
                   error!("Failed to encrypt placeholder: {}", e);
                   continue; // Skip this password
               }
           }
       };
       
       // Add or update the password in the database
       match db.add_or_update_password(
           site,
           username,
           &encrypted_password,
           notes,
           &password_categories,
           update_existing,
       ).await {
           Ok((_, true)) => {
               updated_count += 1;
           },
           Ok((_, false)) => {
               added_count += 1;
           },
           Err(e) => {
               error!("Failed to import password for {}: {}", site, e);
               // Continue with other passwords
           }
       }
   }
   
   // Commit the transaction
   if let Err(e) = db.commit_transaction(tx).await {
       error!("Failed to commit transaction: {}", e);
       return HttpResponse::InternalServerError().json(ImportResponse {
           success: false,
           count: 0,
           added_count: Some(0),
           updated_count: Some(0),
           message: None,
           error: Some(format!("Failed to commit transaction: {}", e)),
       });
   }
   
   // Return success response
   let total = added_count + updated_count;
   HttpResponse::Ok().json(ImportResponse {
       success: true,
       count: total,
       added_count: Some(added_count),
       updated_count: Some(updated_count),
       message: Some(format!(
           "Successfully imported {} passwords ({} new, {} updated)",
           total, added_count, updated_count
       )),
       error: None,
   })
}