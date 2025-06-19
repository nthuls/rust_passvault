// src/api/handlers/privacy.rs

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use crate::privacy::{PrivacyManager, levels::ProtectionLevel};
use crate::api::types::SuccessResponse;
use log::{info, warn, error};
use std::collections::HashMap;
use std::str::FromStr;
use crate::api::types::{
    ProtectionLevelRequest,
    ProtectionLevelResponse,
    PrivacyStatusResponse,
    ProfileListResponse,
    CreateProfileRequest,
    CleanPrivacyDataRequest,
    FirefoxHardeningResponse,
    // FirefoxFingerprintingRequest,
    FingerprintTestResponse,
    FirefoxStatusResponse,
};


// Get current protection level
#[utoipa::path(
    get,
    path = "/privacy/protection-level",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get the current protection level", body = ProtectionLevelResponse),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_protection_level(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let level = privacy_manager.get_protection_level();
            HttpResponse::Ok().json(ProtectionLevelResponse {
                success: true,
                level: level.to_string(),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(ProtectionLevelResponse {
                success: false,
                level: "Unknown".to_string(),
                error: Some(format!("Failed to get protection level: {}", e)),
            })
        }
    }
}

// Set protection level
#[utoipa::path(
    post,
    path = "/privacy/protection-level",
    tag = "Privacy",
    request_body = ProtectionLevelRequest,
    responses(
        (status = 200, description = "Set the desired protection level", body = SuccessResponse),
        (status = 400, description = "Invalid protection level"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn set_protection_level(
    req: web::Json<ProtectionLevelRequest>,
) -> impl Responder {
    let level_str = req.level.clone();
    
    // Parse the protection level
    let level = match ProtectionLevel::from_str(&level_str) {
        Ok(level) => level,
        Err(e) => {
            return HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Invalid protection level: {}", e)),
            });
        }
    };
    
    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            match privacy_manager.set_protection_level(level) {
                Ok(_) => {
                    info!("Set protection level to: {}", level_str);
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Protection level set to {}", level_str)),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to set protection level: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to set protection level: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get privacy status
#[utoipa::path(
    get,
    path = "/privacy/status",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get full privacy status", body = PrivacyStatusResponse),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn get_status(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let status = privacy_manager.get_status();
            HttpResponse::Ok().json(PrivacyStatusResponse {
                success: true,
                status,
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(PrivacyStatusResponse {
                success: false,
                status: crate::privacy::PrivacyStatus {
                    protection_level: ProtectionLevel::Basic,
                    browser_hardening: false,
                    firefox_hardened: false,
                    fingerprint_protection: false,
                    storage_protection: false,
                    network_protection: false,
                },
                error: Some(format!("Failed to get privacy status: {}", e)),
            })
        }
    }
}

// List available profiles
#[utoipa::path(
    get,
    path = "/privacy/profiles",
    tag = "Privacy",
    responses(
        (status = 200, description = "List all privacy profiles", body = ProfileListResponse)
    )
)]
pub async fn list_profiles(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.list_profiles() {
                Ok(profiles) => {
                    HttpResponse::Ok().json(ProfileListResponse {
                        success: true,
                        profiles,
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to list profiles: {}", e);
                    HttpResponse::InternalServerError().json(ProfileListResponse {
                        success: false,
                        profiles: Vec::new(),
                        error: Some(format!("Failed to list profiles: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(ProfileListResponse {
                success: false,
                profiles: Vec::new(),
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get specific profile
#[utoipa::path(
    get,
    path = "/privacy/profiles/{name}",
    tag = "Privacy",
    params(
        ("name" = String, Path, description = "Name of the profile to retrieve")
    ),
    responses(
        (status = 200, description = "Get details of a privacy profile", body = PrivacySettings),
        (status = 404, description = "Profile not found")
    )
)]
pub async fn get_profile(
    req: web::Path<String>,
) -> impl Responder {
    let profile_name = req.into_inner();
    
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.get_profile(&profile_name) {
                Ok(profile) => {
                    HttpResponse::Ok().json(profile)
                },
                Err(e) => {
                    warn!("Failed to get profile {}: {}", profile_name, e);
                    HttpResponse::NotFound().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Profile not found: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Create a new custom profile
#[utoipa::path(
    post,
    path = "/privacy/profiles",
    tag = "Privacy",
    request_body = CreateProfileRequest,
    responses(
        (status = 201, description = "Privacy profile created successfully", body = SuccessResponse),
        (status = 400, description = "Invalid profile data")
    )
)]
pub async fn create_profile(
    req: web::Json<CreateProfileRequest>,
) -> impl Responder {
    // Parse the protection level
    let level = match ProtectionLevel::from_str(&req.level) {
        Ok(level) => level,
        Err(e) => {
            return HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Invalid protection level: {}", e)),
            });
        }
    };
    
    // Create the profile
    let profile = crate::privacy::profiles::PrivacyProfile {
        name: req.name.clone(),
        description: req.description.clone(),
        level: level.clone(),
        settings: req.settings.clone().unwrap_or_else(|| level.get_default_settings()),
    };
    
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.create_profile(profile) {
                Ok(_) => {
                    info!("Created new privacy profile: {}", req.name);
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Privacy profile '{}' created successfully", req.name)),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to create privacy profile: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to create privacy profile: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Update an existing profile
#[utoipa::path(
    put,
    path = "/privacy/profiles/{name}",
    tag = "Privacy",
    request_body = CreateProfileRequest,
    params(
        ("name" = String, Path, description = "Profile name to update")
    ),
    responses(
        (status = 200, description = "Profile updated", body = SuccessResponse),
        (status = 404, description = "Profile not found")
    )
)]
pub async fn update_profile(
    path: web::Path<String>,
    req: web::Json<CreateProfileRequest>,
) -> impl Responder {
    let profile_name = path.into_inner();

    // Parse the protection level
    let level = match ProtectionLevel::from_str(&req.level) {
        Ok(level) => level,
        Err(e) => {
            return HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Invalid protection level: {}", e)),
            });
        }
    };

    // Clone `level` if it's needed more than once
    let settings = req
        .settings
        .clone()
        .unwrap_or_else(|| level.get_default_settings());

    let profile = crate::privacy::profiles::PrivacyProfile {
        name: req.name.clone(),
        description: req.description.clone(),
        level: level.clone(), // Use clone here to fix the move issue
        settings,
    };

    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            match privacy_manager.update_profile(&profile_name, profile) {
                Ok(_) => {
                    info!("Updated privacy profile: {}", profile_name);
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Privacy profile '{}' updated successfully", profile_name)),
                        error: None,
                    })
                }
                Err(e) => {
                    error!("Failed to update privacy profile {}: {}", profile_name, e);
                    let (mut status, message) = match e {
                        // handle specific error types here if needed
                        _ => (HttpResponse::InternalServerError(), "Internal server error".to_string()),
                    };
                    status.json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(message),
                    })
                }
            }
        }
        Err(e) => {
            error!("Failed to initialize privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Failed to initialize Privacy Manager".to_string()),
            })
        }
    }
}

// Apply Firefox hardening
#[utoipa::path(
    post,
    path = "/privacy/firefox/harden",
    tag = "Privacy",
    responses(
        (status = 200, description = "Firefox hardened successfully", body = SuccessResponse)
    )
)]
pub async fn harden_firefox(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.harden_firefox() {
                Ok(applied_settings) => {
                    info!("Applied Firefox hardening with {} settings", applied_settings.len());
                    HttpResponse::Ok().json(FirefoxHardeningResponse {
                        success: true,
                        applied_settings,
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to harden Firefox: {}", e);
                    HttpResponse::InternalServerError().json(FirefoxHardeningResponse {
                        success: false,
                        applied_settings: Vec::new(),
                        error: Some(format!("Failed to harden Firefox: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(FirefoxHardeningResponse {
                success: false,
                applied_settings: Vec::new(),
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Check Firefox hardening status
#[utoipa::path(
    get,
    path = "/privacy/firefox/status",
    tag = "Privacy",
    responses(
        (status = 200, description = "Check if Firefox has been hardened", body = SuccessResponse)
    )
)]
pub async fn check_firefox_status(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.is_firefox_hardened() {
                Ok(is_hardened) => {
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Firefox hardening status: {}", if is_hardened { "enabled" } else { "disabled" })),
                        error: None,
                    })
                },
                Err(e) => {
                    if let crate::privacy::PrivacyError::FirefoxNotFound = e {
                        warn!("Firefox not found: {}", e);
                        return HttpResponse::NotFound().json(SuccessResponse {
                            success: false,
                            message: None,
                            error: Some("Firefox not found on this system".to_string()),
                        });
                    }
                    
                    error!("Failed to check Firefox hardening status: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to check Firefox hardening status: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Clean privacy data
#[utoipa::path(
    post,
    path = "/privacy/clean",
    tag = "Privacy",
    request_body = CleanPrivacyDataRequest,
    responses(
        (status = 200, description = "Privacy-related data cleaned", body = SuccessResponse)
    )
)]
pub async fn clean_privacy_data(
    req: web::Json<CleanPrivacyDataRequest>,
) -> impl Responder {
    // Create cleaning options
    let options = crate::privacy::storage::CleaningOptions {
        clear_cookies: req.clear_cookies.unwrap_or(true),
        clear_history: req.clear_history.unwrap_or(true),
        clear_cache: req.clear_cache.unwrap_or(true),
        clear_local_storage: req.clear_local_storage.unwrap_or(true),
    };
    
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.clean_privacy_data(options) {
                Ok(cleaned_items) => {
                    info!("Cleaned {} privacy items", cleaned_items.len());
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Successfully cleaned {} privacy items", cleaned_items.len())),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to clean privacy data: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to clean privacy data: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get fingerprint settings
#[utoipa::path(
    get,
    path = "/privacy/fingerprint",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get fingerprint protection settings", body = FingerprintSettings)
    )
)]
pub async fn get_fingerprint_settings(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let settings = privacy_manager.get_fingerprint_settings();
            HttpResponse::Ok().json(settings)
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get fingerprint settings: {}", e)),
            })
        }
    }
}

// Set fingerprint settings
#[utoipa::path(
    post,
    path = "/privacy/fingerprint",
    tag = "Privacy",
    request_body = FingerprintSettings,
    responses(
        (status = 200, description = "Fingerprint protection settings updated", body = SuccessResponse)
    )
)]
pub async fn set_fingerprint_settings(
    req: web::Json<crate::privacy::fingerprint::FingerprintSettings>,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            match privacy_manager.set_fingerprint_settings(req.into_inner()) {
                Ok(_) => {
                    info!("Updated fingerprint protection settings");
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some("Fingerprint protection settings updated".to_string()),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to set fingerprint settings: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to set fingerprint settings: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Test current fingerprinting protection
#[utoipa::path(
    get,
    path = "/privacy/fingerprint/test",
    tag = "Privacy",
    responses(
        (status = 200, description = "Returns simulated fingerprint data", body = serde_json::Value)
    )
)]
pub async fn test_fingerprinting(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.test_fingerprint_protection() {
                Ok(test_results) => {
                    let protection_level = if test_results.values().all(|&v| v) {
                        "Strong"
                    } else if test_results.values().filter(|&&v| v).count() > test_results.len() / 2 {
                        "Moderate"
                    } else {
                        "Weak"
                    };
                    
                    HttpResponse::Ok().json(FingerprintTestResponse {
                        success: true,
                        fingerprint_level: protection_level.to_string(),
                        tests: test_results,
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to test fingerprint protection: {}", e);
                    HttpResponse::InternalServerError().json(FingerprintTestResponse {
                        success: false,
                        fingerprint_level: "Unknown".to_string(),
                        tests: HashMap::new(),
                        error: Some(format!("Failed to test fingerprint protection: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(FingerprintTestResponse {
                success: false,
                fingerprint_level: "Unknown".to_string(),
                tests: HashMap::new(),
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get storage settings
#[utoipa::path(
    get,
    path = "/privacy/storage",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get browser storage protection settings", body = StorageSettings)
    )
)]
pub async fn get_storage_settings(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let settings = privacy_manager.get_storage_settings();
            HttpResponse::Ok().json(settings)
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get storage settings: {}", e)),
            })
        }
    }
}

// Set storage settings
#[utoipa::path(
    post,
    path = "/privacy/storage",
    tag = "Privacy",
    request_body = StorageSettings,
    responses(
        (status = 200, description = "Storage settings updated", body = SuccessResponse)
    )
)]
pub async fn set_storage_settings(
    req: web::Json<crate::privacy::storage::StorageSettings>,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            match privacy_manager.set_storage_settings(req.into_inner()) {
                Ok(_) => {
                    info!("Updated storage protection settings");
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some("Storage protection settings updated".to_string()),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to set storage settings: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to set storage settings: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get network settings
#[utoipa::path(
    get,
    path = "/privacy/network",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get network-level privacy settings", body = NetworkSettings)
    )
)]
pub async fn get_network_settings(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let settings = privacy_manager.get_network_settings();
            HttpResponse::Ok().json(settings)
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get network settings: {}", e)),
            })
        }
    }
}

// Set network settings
#[utoipa::path(
    post,
    path = "/privacy/network",
    tag = "Privacy",
    request_body = NetworkSettings,
    responses(
        (status = 200, description = "Network settings updated", body = SuccessResponse)
    )
)]
pub async fn set_network_settings(
    req: web::Json<crate::privacy::network::NetworkSettings>,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            match privacy_manager.set_network_settings(req.into_inner()) {
                Ok(_) => {
                    info!("Updated network protection settings");
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some("Network protection settings updated".to_string()),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to set network settings: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to set network settings: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Configure DNS settings
#[utoipa::path(
    post,
    path = "/privacy/network/dns",
    tag = "Privacy",
    request_body = DnsSettings,
    responses(
        (status = 200, description = "DNS configuration applied", body = SuccessResponse)
    )
)]
pub async fn configure_dns(
    req: web::Json<crate::privacy::network::dns::DnsSettings>,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.configure_dns(req.into_inner()) {
                Ok(_) => {
                    info!("Applied DNS protection settings");
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some("DNS protection settings applied".to_string()),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to configure DNS settings: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to configure DNS settings: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Get detailed Firefox status
#[utoipa::path(
    get,
    path = "/privacy/firefox/details",
    tag = "Privacy",
    responses(
        (status = 200, description = "Detailed Firefox hardening status", body = serde_json::Value)
    )
)]
pub async fn get_firefox_detailed_status(
    _req: HttpRequest,
) -> impl Responder {
    match crate::privacy::browsers::firefox::FirefoxHardener::new() {
        Ok(firefox_hardener) => {
            match firefox_hardener.get_status() {
                Ok(status) => {
                    HttpResponse::Ok().json(FirefoxStatusResponse {
                        success: true,
                        status: Some(status),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to get Firefox status: {}", e);
                    HttpResponse::InternalServerError().json(FirefoxStatusResponse {
                        success: false,
                        status: None,
                        error: Some(format!("Failed to get Firefox status: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            if let crate::privacy::PrivacyError::FirefoxNotFound = e {
                return HttpResponse::NotFound().json(FirefoxStatusResponse {
                    success: false,
                    status: Some(crate::privacy::browsers::firefox::FirefoxStatus {
                        is_installed: false,
                        is_hardened: false,
                        tracking_protection: false,
                        do_not_track: false,
                        resist_fingerprinting: false,
                        canvas_protection: false,
                        webgl_disabled: false,
                        geolocation_disabled: false,
                        webrtc_disabled: false,
                        cookie_restrictions: false,
                        https_only: false,
                    }),
                    error: Some("Firefox not found on this system".to_string()),
                });
            }
            
            error!("Failed to create Firefox hardener: {}", e);
            HttpResponse::InternalServerError().json(FirefoxStatusResponse {
                success: false,
                status: None,
                error: Some(format!("Failed to create Firefox hardener: {}", e)),
            })
        }
    }
}

// Get privacy status
#[utoipa::path(
    get,
    path = "/privacy/status",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get current privacy protection status", body = PrivacyStatusResponse)
    )
)]
pub async fn get_privacy_status(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            let status = privacy_manager.get_status();
            HttpResponse::Ok().json(PrivacyStatusResponse {
                success: true,
                status,
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(PrivacyStatusResponse {
                success: false,
                status: crate::privacy::PrivacyStatus {
                    protection_level: ProtectionLevel::Basic,
                    browser_hardening: false,
                    firefox_hardened: false,
                    fingerprint_protection: false,
                    storage_protection: false,
                    network_protection: false,
                },
                error: Some(format!("Failed to get privacy status: {}", e)),
            })
        }
    }
}

// Delete a profile
#[utoipa::path(
    delete,
    path = "/privacy/profiles/{name}",
    tag = "Privacy",
    params(
        ("name" = String, Path, description = "Name of the profile to delete")
    ),
    responses(
        (status = 200, description = "Profile deleted successfully", body = SuccessResponse),
        (status = 404, description = "Profile not found"),
        (status = 400, description = "Cannot delete standard profile")
    )
)]
pub async fn delete_profile(
    profile_name: web::Path<String>,
) -> impl Responder {
    let profile_name = profile_name.into_inner();
    
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.delete_profile(&profile_name) {
                Ok(_) => {
                    info!("Deleted privacy profile: {}", profile_name);
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Profile '{}' deleted successfully", profile_name)),
                        error: None,
                    })
                },
                Err(e) => {
                    warn!("Failed to delete privacy profile {}: {}", profile_name, e);
                    let (mut status, message) = match e {
                        crate::privacy::PrivacyError::ProfileNotFound(_) => 
                            (HttpResponse::NotFound(), format!("Profile '{}' not found", profile_name)),
                        crate::privacy::PrivacyError::InvalidLevel(_) => 
                            (HttpResponse::BadRequest(), format!("Cannot delete standard profile '{}'", profile_name)),
                        _ => (HttpResponse::InternalServerError(), format!("Failed to delete profile: {}", e)),
                    };
                    status.json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(message),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Apply a profile
#[utoipa::path(
    post,
    path = "/privacy/profiles/{name}/apply",
    tag = "Privacy",
    params(
        ("name" = String, Path, description = "Name of the profile to apply")
    ),
    responses(
        (status = 200, description = "Profile applied successfully", body = SuccessResponse),
        (status = 404, description = "Profile not found")
    )
)]
pub async fn apply_profile(
    profile_name: web::Path<String>,
) -> impl Responder {
    let profile_name = profile_name.into_inner();
    
    match PrivacyManager::new() {
        Ok(mut privacy_manager) => {
            // First check if the profile exists
            match privacy_manager.get_profile(&profile_name) {
                Ok(profile) => {
                    // Apply the profile by setting the protection level
                    match privacy_manager.set_protection_level(profile.level.clone()) {
                        Ok(_) => {
                            info!("Applied privacy profile: {}", profile_name);
                            HttpResponse::Ok().json(SuccessResponse {
                                success: true,
                                message: Some(format!("Profile '{}' applied successfully", profile_name)),
                                error: None,
                            })
                        },
                        Err(e) => {
                            error!("Failed to apply privacy profile {}: {}", profile_name, e);
                            HttpResponse::InternalServerError().json(SuccessResponse {
                                success: false,
                                message: None,
                                error: Some(format!("Failed to apply profile: {}", e)),
                            })
                        }
                    }
                },
                Err(e) => {
                    warn!("Failed to find privacy profile {}: {}", profile_name, e);
                    HttpResponse::NotFound().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Profile '{}' not found", profile_name)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}

// Check Firefox hardening status
#[utoipa::path(
    get,
    path = "/privacy/firefox/hardening",
    tag = "Privacy",
    responses(
        (status = 200, description = "Get Firefox hardening status", body = SuccessResponse)
    )
)]
pub async fn check_firefox_hardening(
    _req: HttpRequest,
) -> impl Responder {
    match PrivacyManager::new() {
        Ok(privacy_manager) => {
            match privacy_manager.is_firefox_hardened() {
                Ok(is_hardened) => {
                    HttpResponse::Ok().json(SuccessResponse {
                        success: true,
                        message: Some(format!("Firefox hardening status: {}", if is_hardened { "active" } else { "inactive" })),
                        error: None,
                    })
                },
                Err(e) => {
                    error!("Failed to check Firefox hardening status: {}", e);
                    HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to check Firefox hardening status: {}", e)),
                    })
                }
            }
        },
        Err(e) => {
            error!("Failed to create privacy manager: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create privacy manager: {}", e)),
            })
        }
    }
}