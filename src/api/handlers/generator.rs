// src/api/handlers/generator.rs

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use crate::models::PasswordGenerationOptions;
use crate::generators::PasswordGenerator;
use crate::crypto;
use crate::api::types::{
    PasswordGenerationRequest, PasswordGenerationResponse,
    PasswordAnalysisResponse
};
use crate::api::utils::extract_token;
// use log::{info, warn, error, debug};

/// Generate a secure password
///
/// Generates a secure password based on the provided options.
#[utoipa::path(
    post,
    path = "/generator/password",
    tag = "Generator",
    security(
        ("bearer_auth" = [])
    ),
    request_body = PasswordGenerationRequest,
    responses(
        (status = 200, description = "Generated password", body = PasswordGenerationResponse),
        (status = 401, description = "Unauthorized", body = PasswordGenerationResponse),
        (status = 500, description = "Server error", body = PasswordGenerationResponse)
    )
)]
pub async fn generate_password(
    req: HttpRequest,
    generation_req: web::Json<PasswordGenerationRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    // Extract token (for authentication, but we don't actually need it for generation)
    let (_token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return Ok(HttpResponse::Unauthorized().json(PasswordGenerationResponse {
                success: false,
                password: None,
                strength: None,
                error: Some(format!("Authentication error: {}", e)),
            }));
        }
    };

    // Create options with defaults or provided values
    let options = PasswordGenerationOptions {
        length: generation_req.length.unwrap_or(16),
        include_uppercase: generation_req.include_uppercase.unwrap_or(true),
        include_lowercase: generation_req.include_lowercase.unwrap_or(true),
        include_numbers: generation_req.include_numbers.unwrap_or(true),
        include_symbols: generation_req.include_symbols.unwrap_or(true),
        exclude_similar: generation_req.exclude_similar.unwrap_or(false),
        memorable: generation_req.memorable.unwrap_or(false),
    };

    // Validate options
    if options.length < 4 {
        return Ok(HttpResponse::BadRequest().json(PasswordGenerationResponse {
            success: false,
            password: None,
            strength: None,
            error: Some("Password length must be at least 4 characters".to_string()),
        }));
    }

    if options.length > 100 {
        return Ok(HttpResponse::BadRequest().json(PasswordGenerationResponse {
            success: false,
            password: None,
            strength: None,
            error: Some("Password length must be at most 100 characters".to_string()),
        }));
    }

    if !options.include_uppercase &&
       !options.include_lowercase &&
       !options.include_numbers &&
       !options.include_symbols {
        return Ok(HttpResponse::BadRequest().json(PasswordGenerationResponse {
            success: false,
            password: None,
            strength: None,
            error: Some("At least one character type must be included".to_string()),
        }));
    }

    // Create password generator
    let generator = PasswordGenerator::new();

    // Generate password
    let password = match generator.generate_password(&options) {
        Ok(pwd) => pwd,
        Err(e) => {
            return Ok(HttpResponse::InternalServerError().json(PasswordGenerationResponse {
                success: false,
                password: None,
                strength: None,
                error: Some(format!("Failed to generate password: {}", e)),
            }));
        }
    };

    // Calculate strength
    let strength = crypto::analyze_password_strength(&password);

    // Return the generated password
    Ok(HttpResponse::Ok().json(PasswordGenerationResponse {
        success: true,
        password: Some(password),
        strength: Some(strength),
        error: None,
    }))
}
/// Analyze password strength
///
/// Analyzes the strength of a password and provides feedback.
#[utoipa::path(
    get,
    path = "/generator/analysis/{pwd}",
    tag = "Generator",
    params(
        ("pwd" = String, Path, description = "Password to analyze")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Password analysis result", body = PasswordAnalysisResponse),
        (status = 401, description = "Unauthorized", body = PasswordAnalysisResponse),
        (status = 500, description = "Server error", body = PasswordAnalysisResponse)
    )
)]
pub async fn analyze_password(
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    // Extract token
    let (_token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(PasswordAnalysisResponse {
                success: false,
                strength: 0,
                feedback: vec![],
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };

    // Get the password from the path
    let password = path.into_inner();

    // URL decode the password if needed
    let decoded_password = match urlencoding::decode(&password) {
        Ok(decoded) => decoded.to_string(),
        Err(_) => password.clone(),
    };

    // Calculate strength
    let strength = crypto::analyze_password_strength(&decoded_password);

    // Generate feedback based on strength
    let mut feedback = Vec::new();

    if strength < 20 {
        feedback.push("Very weak password".to_string());
        feedback.push("Consider using a longer password with mixed character types".to_string());
    } else if strength < 40 {
        feedback.push("Weak password".to_string());
        if !decoded_password.chars().any(|c| c.is_uppercase()) {
            feedback.push("Add uppercase letters for better security".to_string());
        }
        if !decoded_password.chars().any(|c| c.is_numeric()) {
            feedback.push("Add numbers for better security".to_string());
        }
        if !decoded_password.chars().any(|c| !c.is_alphanumeric()) {
            feedback.push("Add symbols for better security".to_string());
        }
        if decoded_password.len() < 12 {
            feedback.push("Increase password length to at least 12 characters".to_string());
        }
    } else if strength < 60 {
        feedback.push("Moderate password".to_string());
        if decoded_password.len() < 12 {
            feedback.push("Consider increasing password length to at least 12 characters".to_string());
        }
        if !decoded_password.chars().any(|c| !c.is_alphanumeric()) {
            feedback.push("Add symbols for better security".to_string());
        }
    } else if strength < 80 {
        feedback.push("Strong password".to_string());
        if decoded_password.len() < 16 {
            feedback.push("For maximum security, consider increasing length to 16+ characters".to_string());
        }
    } else {
        feedback.push("Very strong password".to_string());
        feedback.push("Excellent password strength!".to_string());
    }

    // Check for common patterns
    if decoded_password.len() >= 3 {
        let mut consecutive_chars = 1;
        let mut consecutive_nums = 1;

        let mut chars = decoded_password.chars().peekable();
        if let Some(mut prev) = chars.next() {
            while let Some(curr) = chars.next() {
                if curr as u8 == prev as u8 + 1 {
                    if curr.is_ascii_alphabetic() && prev.is_ascii_alphabetic() {
                        consecutive_chars += 1;
                    } else {
                        consecutive_chars = 1;
                    }

                    if curr.is_ascii_digit() && prev.is_ascii_digit() {
                        consecutive_nums += 1;
                    } else {
                        consecutive_nums = 1;
                    }
                } else {
                    consecutive_chars = 1;
                    consecutive_nums = 1;
                }

                if consecutive_chars >= 3 {
                    feedback.push("Avoid using consecutive letters (e.g., 'abc')".to_string());
                    break;
                }

                if consecutive_nums >= 3 {
                    feedback.push("Avoid using consecutive numbers (e.g., '123')".to_string());
                    break;
                }

                prev = curr;
            }
        }
    }

    // Return the analysis
    HttpResponse::Ok().json(PasswordAnalysisResponse {
        success: true,
        strength,
        feedback,
        error: None,
    })
}