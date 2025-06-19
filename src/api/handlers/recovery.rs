// src/api/handlers/recovery.rs
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use crate::core::vault::Vault;
use crate::recovery::{RecoveryManager, RecoveryError, SecurityQuestion};
use crate::api::types::{
    RecoveryStatus, EmailSetupRequest, SmsSetupRequest, SecurityQuestionsSetupRequest,
    RecoveryInitiateRequest, VerifyTokenRequest, VerifyQuestionsRequest, ResetPasswordRequest,
    SuccessResponse
};
use log::{info, warn, error};
use crate::api::utils::extract_token;

/// Get recovery status
///
/// Returns the current recovery settings.
#[utoipa::path(
    get,
    path = "/recovery/status",
    tag = "Recovery",
    responses(
        (status = 200, description = "Recovery settings fetched", body = RecoveryStatus),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_status(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    // Extract token
    let result = extract_token(&req);
    if result.is_err() {
        return HttpResponse::Unauthorized().json(RecoveryStatus {
            success: false,
            email_recovery_enabled: false,
            sms_recovery_enabled: false,
            security_questions_enabled: false,
            recovery_email: None,
            recovery_phone_masked: None,
            security_questions_count: 0,
            error: Some("Authentication required".to_string()),
        });
    }

    // Get database reference
    let db = vault.get_db_ref();

    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));

    // Get recovery status
    match recovery_manager.get_status().await {
        Ok((email_enabled, sms_enabled, questions_enabled, email, phone, question_count)) => {
            HttpResponse::Ok().json(RecoveryStatus {
                success: true,
                email_recovery_enabled: email_enabled,
                sms_recovery_enabled: sms_enabled,
                security_questions_enabled: questions_enabled,
                recovery_email: email,
                recovery_phone_masked: phone,
                security_questions_count: question_count,
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to get recovery status: {}", e);
            HttpResponse::InternalServerError().json(RecoveryStatus {
                success: false,
                email_recovery_enabled: false,
                sms_recovery_enabled: false,
                security_questions_enabled: false,
                recovery_email: None,
                recovery_phone_masked: None,
                security_questions_count: 0,
                error: Some(format!("Failed to get recovery status: {}", e)),
            })
        }
    }
}

/// Set up email recovery
///
/// Configures recovery via email.
#[utoipa::path(
    post,
    path = "/recovery/setup/email",
    request_body = EmailSetupRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Email recovery setup complete", body = SuccessResponse),
        (status = 400, description = "Invalid email or missing data"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn setup_email(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    email_req: web::Json<EmailSetupRequest>,
) -> impl Responder {
    // Extract token
    if extract_token(&req).is_err() {
        return HttpResponse::Unauthorized().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Authentication required".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Set up email recovery
    match recovery_manager.setup_email(&email_req.email).await {
        Ok(_) => {
            info!("Email recovery set up for: {}", email_req.email);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Email recovery set up successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to set up email recovery: {}", e);
            HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to set up email recovery: {}", e)),
            })
        }
    }
}

/// Set up SMS recovery
///
/// Configures recovery via SMS.
#[utoipa::path(
    post,
    path = "/recovery/setup/sms",
    request_body = SmsSetupRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "SMS recovery setup complete", body = SuccessResponse),
        (status = 400, description = "Invalid phone number or data"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn setup_sms(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    sms_req: web::Json<SmsSetupRequest>,
) -> impl Responder {
    // Extract token
    if extract_token(&req).is_err() {
        return HttpResponse::Unauthorized().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Authentication required".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Set up SMS recovery
    match recovery_manager.setup_sms(&sms_req.phone).await {
        Ok(_) => {
            info!("SMS recovery set up for: {}", sms_req.phone);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("SMS recovery set up successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to set up SMS recovery: {}", e);
            HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to set up SMS recovery: {}", e)),
            })
        }
    }
}

/// Set up security questions
///
/// Configures recovery via security questions.
#[utoipa::path(
    post,
    path = "/recovery/setup/questions",
    request_body = SecurityQuestionsSetupRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Security questions set", body = SuccessResponse),
        (status = 400, description = "Missing or invalid questions"),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn setup_questions(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    questions_req: web::Json<SecurityQuestionsSetupRequest>,
) -> impl Responder {
    // Extract token
    if extract_token(&req).is_err() {
        return HttpResponse::Unauthorized().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Authentication required".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Set up security questions
    let questions: Vec<SecurityQuestion> = questions_req.questions.iter()
        .map(|q| SecurityQuestion {
            question: q.question.clone(),
            answer: q.answer.clone(),
        })
        .collect();
    
    match recovery_manager.setup_security_questions(&questions).await {
        Ok(_) => {
            info!("Security questions set up: {} questions", questions.len());
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Security questions set up successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to set up security questions: {}", e);
            HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to set up security questions: {}", e)),
            })
        }
    }
}

/// Disable recovery
///
/// Disables all recovery options.
#[utoipa::path(
    put,
    path = "/recovery/disable",
    tag = "Recovery",
    responses(
        (status = 200, description = "Recovery options disabled", body = SuccessResponse),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn disable_recovery(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    // Extract token
    if extract_token(&req).is_err() {
        return HttpResponse::Unauthorized().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Authentication required".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Disable recovery
    match recovery_manager.disable_recovery().await {
        Ok(_) => {
            info!("Recovery options disabled");
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Recovery options disabled successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to disable recovery options: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to disable recovery options: {}", e)),
            })
        }
    }
}

/// Initiate recovery process
///
/// Starts the account recovery process by sending a verification token.
#[utoipa::path(
    post,
    path = "/recovery/initiate",
    request_body = RecoveryInitiateRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Recovery process initiated", body = SuccessResponse),
        (status = 400, description = "Invalid recovery initiation data")
    )
)]
pub async fn initiate_recovery(
    vault: web::Data<Arc<Vault>>,
    recovery_req: web::Json<RecoveryInitiateRequest>,
) -> impl Responder {
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Initiate recovery
    match recovery_manager.initiate_recovery(&recovery_req.method, &recovery_req.identifier).await {
        Ok((recovery_id, token)) => {
            info!("Recovery initiated for method: {}", recovery_req.method);
            
            #[cfg(debug_assertions)]
            // In debug mode, include the token in the response (for testing)
            {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Recovery process initiated. Check your email or phone for the verification code.",
                    "recovery_id": recovery_id,
                    "debug_token": token, // Only in debug mode
                    "error": null
                }))
            }
            
            #[cfg(not(debug_assertions))]
            // In production, don't include the token
            {
                HttpResponse::Ok().json(serde_json::json!({
                    "success": true,
                    "message": "Recovery process initiated. Check your email or phone for the verification code.",
                    "recovery_id": recovery_id,
                    "error": null
                }))
            }
        },
        Err(e) => {
            let (mut status, message) = match e {
                RecoveryError::InvalidMethod(_) => 
                    (HttpResponse::BadRequest(), format!("Invalid recovery method: {}", e)),
                RecoveryError::InvalidIdentifier => 
                    (HttpResponse::BadRequest(), "Invalid identifier provided".to_string()),
                RecoveryError::NotEnabled => 
                    (HttpResponse::BadRequest(), "Recovery not enabled for this method".to_string()),
                RecoveryError::SmsError(msg) => 
                    (HttpResponse::ServiceUnavailable(), format!("SMS service error: {}", msg)),
                RecoveryError::EmailError(msg) => 
                    (HttpResponse::ServiceUnavailable(), format!("Email service error: {}", msg)),
                _ => (HttpResponse::InternalServerError(), format!("Recovery error: {}", e)),
            };
            
            error!("Failed to initiate recovery: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Verify recovery token
///
/// Verifies the token sent during the recovery process.
#[utoipa::path(
    post,
    path = "/recovery/verify/email",
    request_body = VerifyTokenRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Email verification successful", body = SuccessResponse),
        (status = 400, description = "Invalid or expired token")
    )
)]
pub async fn verify_email(
    vault: web::Data<Arc<Vault>>,
    verify_req: web::Json<VerifyTokenRequest>,
) -> impl Responder {
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Verify token
    match recovery_manager.verify_token(&verify_req.recovery_id, &verify_req.token).await {
        Ok(_) => {
            info!("Email verification successful for recovery ID: {}", verify_req.recovery_id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Email verification successful".to_string()),
                error: None,
            })
        },
        Err(e) => {
            let (mut status, message) = match e {
                RecoveryError::InvalidToken => 
                    (HttpResponse::BadRequest(), "Invalid verification token".to_string()),
                RecoveryError::SessionExpired => 
                    (HttpResponse::BadRequest(), "Verification token expired".to_string()),
                RecoveryError::TooManyAttempts => 
                    (HttpResponse::TooManyRequests(), "Too many failed verification attempts".to_string()),
                _ => (HttpResponse::InternalServerError(), format!("Verification error: {}", e)),
            };
            
            warn!("Email verification failed: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Verify SMS token
///
/// Verifies the SMS token sent during the recovery process.
#[utoipa::path(
    post,
    path = "/recovery/verify/sms",
    request_body = VerifyTokenRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "SMS verification successful", body = SuccessResponse),
        (status = 400, description = "Invalid or expired token")
    )
)]
pub async fn verify_sms(
    vault: web::Data<Arc<Vault>>,
    verify_req: web::Json<VerifyTokenRequest>,
) -> impl Responder {
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Verify token (same logic as email verification)
    match recovery_manager.verify_token(&verify_req.recovery_id, &verify_req.token).await {
        Ok(_) => {
            info!("SMS verification successful for recovery ID: {}", verify_req.recovery_id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("SMS verification successful".to_string()),
                error: None,
            })
        },
        Err(e) => {
            let (mut status, message) = match e {
                RecoveryError::InvalidToken => 
                    (HttpResponse::BadRequest(), "Invalid verification token".to_string()),
                RecoveryError::SessionExpired => 
                    (HttpResponse::BadRequest(), "Verification token expired".to_string()),
                RecoveryError::TooManyAttempts => 
                    (HttpResponse::TooManyRequests(), "Too many failed verification attempts".to_string()),
                _ => (HttpResponse::InternalServerError(), format!("Verification error: {}", e)),
            };
            
            warn!("SMS verification failed: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Verify security questions
///
/// Verifies the answers to security questions as part of the recovery process.
#[utoipa::path(
    post,
    path = "/recovery/verify/questions",
    request_body = VerifyQuestionsRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Security questions verified", body = SuccessResponse),
        (status = 400, description = "Invalid answers or questions")
    )
)]
pub async fn verify_questions(
    vault: web::Data<Arc<Vault>>,
    verify_req: web::Json<VerifyQuestionsRequest>,
) -> impl Responder {
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Verify security questions
    match recovery_manager.verify_questions(&verify_req.recovery_id, &verify_req.answers).await {
        Ok(_) => {
            info!("Security questions verified for recovery ID: {}", verify_req.recovery_id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Security questions verified successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            let (mut status, message) = match e {
                RecoveryError::InvalidToken => 
                    (HttpResponse::BadRequest(), "Invalid recovery session or token verification required first".to_string()),
                RecoveryError::InvalidAnswers => 
                    (HttpResponse::BadRequest(), "Incorrect answers to security questions".to_string()),
                RecoveryError::NotEnabled => 
                    (HttpResponse::BadRequest(), "Security questions not configured".to_string()),
                _ => (HttpResponse::InternalServerError(), format!("Verification error: {}", e)),
            };
            
            warn!("Security questions verification failed: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}

/// Reset password
///
/// Resets the master password after successful verification.
#[utoipa::path(
    post,
    path = "/recovery/reset",
    request_body = ResetPasswordRequest,
    tag = "Recovery",
    responses(
        (status = 200, description = "Password reset successful", body = SuccessResponse),
        (status = 400, description = "Invalid token or new password")
    )
)]
pub async fn reset_password(
    vault: web::Data<Arc<Vault>>,
    reset_req: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    // Validate password strength
    if reset_req.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Password must be at least 8 characters long".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create recovery manager
    let recovery_manager = RecoveryManager::new(Arc::clone(&db));
    
    // Reset password
    match recovery_manager.reset_password(&reset_req.recovery_id, &reset_req.new_password).await {
        Ok(_) => {
            info!("Password reset successful for recovery ID: {}", reset_req.recovery_id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Master password reset successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            let (mut status, message) = match e {
                RecoveryError::InvalidToken => 
                    (HttpResponse::BadRequest(), "Invalid recovery session or verification required".to_string()),
                _ => (HttpResponse::InternalServerError(), format!("Password reset error: {}", e)),
            };
            
            error!("Password reset failed: {}", message);
            status.json(SuccessResponse {
                success: false,
                message: None,
                error: Some(message),
            })
        }
    }
}