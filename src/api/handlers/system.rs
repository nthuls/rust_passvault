// src/api/handlers/system.rs
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use crate::core::vault::Vault;
use crate::system::{SystemManager, FirejailManager};
use crate::logging::Logger;
use crate::api::utils::extract_token;
use crate::api::types::SuccessResponse;
use crate::logging::LogFilter;
use log::{info, error};

/// Get system status
#[utoipa::path(
    get,
    path = "/system/status",
    tag = "System",
    responses(
        (status = 200, description = "Get current system status"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_status(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    // Validate token (just check if it's valid, we don't need the session ID)
    let (_, _) = match extract_token(&req) {
        Ok(token_data) => token_data,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Create system manager
    let mut system_manager = SystemManager::new();
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Get system status (vault is unlocked since we have a valid token)
    match system_manager.get_system_status(&db, false).await {
        Ok(status) => {
            HttpResponse::Ok().json(status)
        },
        Err(e) => {
            error!("Failed to get system status: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get system status: {}", e)),
            })
        }
    }
}

/// Get system logs
#[utoipa::path(
    get,
    path = "/system/logs",
    tag = "System",
    params(
        ("level" = Option<String>, Query, description = "Filter by log level (e.g., info, error)"),
        ("limit" = Option<usize>, Query, description = "Maximum number of logs to return")
    ),
    responses(
        (status = 200, description = "Retrieve filtered logs"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_logs(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    filter: web::Query<LogFilter>,
) -> impl Responder {
    // Validate token
    let (_, _) = match extract_token(&req) {
        Ok(token_data) => token_data,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get config directory
    let config_dir = match crate::utils::get_app_config_dir() {
        Some(dir) => dir,
        None => {
            error!("Failed to get config directory");
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Failed to get config directory".to_string()),
            });
        }
    };
    
    // Create logger
    let logger = match Logger::new(config_dir.join("logs")) {
        Ok(logger) => logger,
        Err(e) => {
            error!("Failed to create logger: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create logger: {}", e)),
            });
        }
    };
    
    // Get logs with filter
    match logger.get_logs(&filter) {
        Ok(logs) => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "logs": logs,
                "total": logs.len(),
                "error": null
            }))
        },
        Err(e) => {
            error!("Failed to get logs: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get logs: {}", e)),
            })
        }
    }
}

/// Launch a browser in a Firejail sandbox
#[utoipa::path(
    post,
    path = "/system/firejail/browser",
    tag = "System",
    request_body(content = LaunchBrowserRequest, description = "Details for launching browser sandbox"),
    responses(
        (status = 200, description = "Browser launched in Firejail sandbox"),
        (status = 400, description = "Invalid request parameters"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Failed to launch sandbox")
    )
)]
pub async fn launch_browser_sandbox(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    launch_req: web::Json<crate::system::LaunchBrowserRequest>,
) -> impl Responder {
    // Validate token
    let (_, _) = match extract_token(&req) {
        Ok(token_data) => token_data,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get config directory
    let config_dir = match crate::utils::get_app_config_dir() {
        Some(dir) => dir,
        None => {
            error!("Failed to get config directory");
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Failed to get config directory".to_string()),
            });
        }
    };
    
    // Create Firejail manager
    let mut firejail_manager = FirejailManager::new(config_dir);
    
    // Check if Firejail is installed
    if !firejail_manager.is_installed() {
        let instructions = FirejailManager::get_installation_instructions();
        
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Firejail is not installed",
            "installation_instructions": instructions
        }));
    }
    
    // Update active browsers list
    firejail_manager.update_active_browsers();
    
    // Launch browser
    match firejail_manager.launch_browser(&launch_req) {
        Ok(browser) => {
            info!("Browser launched in sandbox: {} (PID: {})", 
                  browser.browser_name, browser.process_id);
            
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "browser": browser,
                "message": format!("{} launched in sandbox", browser.browser_name)
            }))
        },
        Err(e) => {
            error!("Failed to launch browser in sandbox: {}", e);
            
            let (mut status, message) = match e {
                crate::system::FirejailError::NotInstalled => 
                    (HttpResponse::BadRequest(), "Firejail is not installed".to_string()),
                crate::system::FirejailError::BrowserNotFound(browser) => 
                    (HttpResponse::BadRequest(), format!("Browser not found: {}", browser)),
                _ => (HttpResponse::InternalServerError(), format!("Failed to launch browser: {}", e)),
            };
            
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Check Firejail sandbox status
#[utoipa::path(
    get,
    path = "/system/firejail/status",
    tag = "System",
    responses(
        (status = 200, description = "Check sandbox (Firejail) status"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn check_sandbox_status(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    // Validate token
    let (_, _) = match extract_token(&req) {
        Ok(token_data) => token_data,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get config directory
    let config_dir = match crate::utils::get_app_config_dir() {
        Some(dir) => dir,
        None => {
            error!("Failed to get config directory");
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Failed to get config directory".to_string()),
            });
        }
    };
    
    // Create Firejail manager
    let mut firejail_manager = FirejailManager::new(config_dir);
    
    // Update active browsers list
    firejail_manager.update_active_browsers();
    
    // Get status
    let status = firejail_manager.get_status();
    
    // Add installation instructions if not installed
    if !status.installed {
        let instructions = FirejailManager::get_installation_instructions();
        
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "status": status,
            "installation_instructions": instructions
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "status": status
        }))
    }
}