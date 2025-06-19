// src/recovery/mod.rs
use rand::{thread_rng, Rng};
use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use uuid::Uuid;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::db::Database;
use crate::api::types::BongaSmsResponse;
use lazy_static::lazy_static;
use crate::core::vault::Vault;

// Recovery error types
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Database error: {0}")]
    DbError(#[from] crate::db::DbError),
    
    #[error("Invalid recovery method: {0}")]
    InvalidMethod(String),
    
    #[error("Invalid recovery token")]
    InvalidToken,
    
    #[error("Invalid recovery identifier")]
    InvalidIdentifier,
    
    #[error("Recovery not enabled for this method")]
    NotEnabled,
    
    #[error("Recovery session expired")]
    SessionExpired,
    
    #[error("Too many failed attempts")]
    TooManyAttempts,
    
    #[error("Recovery already in progress")]
    AlreadyInProgress,
    
    #[error("Invalid answers to security questions")]
    InvalidAnswers,
    
    #[error("SMS service error: {0}")]
    SmsError(String),
    
    #[error("Email service error: {0}")]
    EmailError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

// Recovery session tracking
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    pub id: String,
    pub method: String,
    pub identifier: String,
    pub token: String,
    pub token_expiry: DateTime<Utc>,
    pub verified_token: bool,
    pub verified_questions: bool,
    pub attempts: usize,
    pub created_at: DateTime<Utc>,
}

// In-memory store for recovery sessions
lazy_static! {
    static ref RECOVERY_SESSIONS: Arc<Mutex<HashMap<String, RecoverySession>>> = {
        Arc::new(Mutex::new(HashMap::new()))
    };
}

// Recovery manager
pub struct RecoveryManager {
    db: Arc<Database>,
}

impl RecoveryManager {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
    
    // Get recovery status
    pub async fn get_status(&self) -> Result<(bool, bool, bool, Option<String>, Option<String>, usize), RecoveryError> {
        // Check if email recovery is enabled
        let email_enabled = self.db.get_config_value("recovery_email").await?.is_some();
        
        // Check if SMS recovery is enabled
        let sms_enabled = self.db.get_config_value("recovery_phone").await?.is_some();
        
        // Check if security questions are enabled
        let questions_json = self.db.get_config_value("security_questions").await?;
        let security_questions_enabled = questions_json.is_some();
        
        // Get masked email
        let recovery_email = match self.db.get_config_value("recovery_email").await? {
            Some(email) => Some(email),
            None => None,
        };
        
        // Get masked phone number
        let recovery_phone = match self.db.get_config_value("recovery_phone").await? {
            Some(phone) => Some(mask_phone_number(&phone)),
            None => None,
        };
        
        // Count security questions
        let question_count = if let Some(json) = questions_json {
            // Parse questions JSON
            let questions: Vec<SecurityQuestion> = serde_json::from_str(&json)
                .map_err(|_| RecoveryError::InvalidMethod("Invalid security questions format".into()))?;
            questions.len()
        } else {
            0
        };
        
        Ok((email_enabled, sms_enabled, security_questions_enabled, 
            recovery_email, recovery_phone, question_count))
    }
    
    // Set up email recovery
    pub async fn setup_email(&self, email: &str) -> Result<(), RecoveryError> {
        // Validate email (basic validation)
        if !email.contains('@') || !email.contains('.') {
            return Err(RecoveryError::InvalidIdentifier);
        }
        
        // Store email in database
        self.db.store_config_value("recovery_email", email).await?;
        
        Ok(())
    }
    
    // Set up SMS recovery
    pub async fn setup_sms(&self, phone: &str) -> Result<(), RecoveryError> {
        // Validate phone number format (basic validation)
        if !phone.starts_with('+') || phone.len() < 10 {
            return Err(RecoveryError::InvalidIdentifier);
        }
        
        // Store phone in database
        self.db.store_config_value("recovery_phone", phone).await?;
        
        Ok(())
    }
    
    // Set up security questions
    pub async fn setup_security_questions(&self, questions: &[SecurityQuestion]) -> Result<(), RecoveryError> {
        // Validate questions (at least 3 questions)
        if questions.len() < 3 {
            return Err(RecoveryError::InvalidMethod("At least 3 security questions required".into()));
        }
        
        // Serialize questions to JSON
        let questions_json = serde_json::to_string(questions)
            .map_err(|_| RecoveryError::InvalidMethod("Failed to serialize security questions".into()))?;
        
        // Store questions in database
        self.db.store_config_value("security_questions", &questions_json).await?;
        
        Ok(())
    }
    
    // Disable recovery
    pub async fn disable_recovery(&self) -> Result<(), RecoveryError> {
        // Remove all recovery options
        self.db.store_config_value("recovery_email", "").await?;
        self.db.store_config_value("recovery_phone", "").await?;
        self.db.store_config_value("security_questions", "").await?;
        
        Ok(())
    }
    
    // Initiate recovery process
    pub async fn initiate_recovery(&self, method: &str, identifier: &str) -> Result<(String, String), RecoveryError> {
        // Validate method
        if method != "email" && method != "sms" {
            return Err(RecoveryError::InvalidMethod(format!("Invalid recovery method: {}", method)));
        }
        
        // Check if recovery is enabled for this method
        if method == "email" {
            let stored_email = self.db.get_config_value("recovery_email").await?;
            
            if stored_email.as_ref().map_or(true, |e| e.is_empty()) {
                return Err(RecoveryError::NotEnabled);
            }

            if stored_email.as_ref().unwrap() != identifier {
                return Err(RecoveryError::InvalidIdentifier);
            }

        } else if method == "sms" {
            let stored_phone = self.db.get_config_value("recovery_phone").await?;
            
            if stored_phone.as_ref().map_or(true, |p| p.is_empty()) {
                return Err(RecoveryError::NotEnabled);
            }

            if stored_phone.as_ref().unwrap() != identifier {
                return Err(RecoveryError::InvalidIdentifier);
            }
        }

        
        // Generate a recovery token (6-digit code)
        let token = generate_recovery_token();
        
        // Create a recovery session
        let session_id = Uuid::new_v4().to_string();
        let recovery_session = RecoverySession {
            id: session_id.clone(),
            method: method.to_string(),
            identifier: identifier.to_string(),
            token: token.clone(),
            token_expiry: Utc::now() + Duration::minutes(15), // Token valid for 15 minutes
            verified_token: false,
            verified_questions: false,
            attempts: 0,
            created_at: Utc::now(),
        };
        
        // Store the recovery session
        RECOVERY_SESSIONS.lock().unwrap().insert(session_id.clone(), recovery_session);
        
        // Send the token via the appropriate method
        if method == "email" {
            // TODO: Implement email sending here
            // For now, we'll just log it
            log::info!("Recovery token for {}: {}", identifier, token);
        } else if method == "sms" {
            // Send the token via SMS using Bonga SMS
            let sms_message = format!("Your RustVault recovery code is: {}. Valid for 15 minutes.", token);
            
            let response = send_sms(identifier, &sms_message).await?;
            
            if response.status != 222 {
                return Err(RecoveryError::SmsError(response.status_message));
            }
            
            log::info!("Recovery SMS sent to {}: {}", identifier, response.status_message);
        }
        
        // Return the session ID and token (for testing only - in production only return session ID)
        Ok((session_id, token))
    }
    
    // Verify recovery token
    pub async fn verify_token(&self, recovery_id: &str, token: &str) -> Result<(), RecoveryError> {
        // Get the recovery session
        let mut sessions = RECOVERY_SESSIONS.lock().unwrap();
        let session = sessions.get_mut(recovery_id)
            .ok_or(RecoveryError::InvalidToken)?;
        
        // Check if token is expired
        if Utc::now() > session.token_expiry {
            return Err(RecoveryError::SessionExpired);
        }
        
        // Check if too many attempts
        if session.attempts >= 3 {
            return Err(RecoveryError::TooManyAttempts);
        }
        
        // Increment attempts
        session.attempts += 1;
        
        // Verify token
        if session.token != token {
            return Err(RecoveryError::InvalidToken);
        }
        
        // Mark token as verified
        session.verified_token = true;
        
        Ok(())
    }
    
    // Verify security questions
    pub async fn verify_questions(&self, recovery_id: &str, answers: &[String]) -> Result<(), RecoveryError> {
        // Get the recovery session
        let mut sessions = RECOVERY_SESSIONS.lock().unwrap();
        let session = sessions.get_mut(recovery_id)
            .ok_or(RecoveryError::InvalidToken)?;
        
        // Check if token is verified
        if !session.verified_token {
            return Err(RecoveryError::InvalidToken);
        }
        
        // Get stored security questions
        let questions_json = self.db.get_config_value("security_questions").await?
            .ok_or(RecoveryError::NotEnabled)?;
        
        // Parse questions JSON
        let questions: Vec<SecurityQuestion> = serde_json::from_str(&questions_json)
            .map_err(|_| RecoveryError::InvalidMethod("Invalid security questions format".into()))?;
        
        // Check if we have the right number of answers
        if answers.len() != questions.len() {
            return Err(RecoveryError::InvalidAnswers);
        }
        
        // Verify answers (simple case-insensitive comparison)
        let mut correct_answers = 0;
        for (i, answer) in answers.iter().enumerate() {
            if answer.to_lowercase() == questions[i].answer.to_lowercase() {
                correct_answers += 1;
            }
        }
        
        // Require at least 2/3 of answers to be correct
        let threshold = (questions.len() as f32 * 2.0 / 3.0).ceil() as usize;
        if correct_answers < threshold {
            return Err(RecoveryError::InvalidAnswers);
        }
        
        // Mark questions as verified
        session.verified_questions = true;
        
        Ok(())
    }
    
    // Reset password
    pub async fn reset_password(&self, recovery_id: &str, new_password: &str) -> Result<(), RecoveryError> {
        // Get the recovery session
        let sessions = RECOVERY_SESSIONS.lock().unwrap();
        let session = sessions.get(recovery_id)
            .ok_or(RecoveryError::InvalidToken)?;
        
        // Check if token and questions are verified
        if !session.verified_token || !session.verified_questions {
            return Err(RecoveryError::InvalidToken);
        }
        
        // Create a vault instance
        let vault = Vault::new(Arc::clone(&self.db));
        
        // Reset the master password
        match vault.reset_master_password(new_password).await {
            Ok(_) => {
                log::info!("Password reset for {}", session.identifier);
                
                // Remove the recovery session
                drop(sessions);
                RECOVERY_SESSIONS.lock().unwrap().remove(recovery_id);
                
                Ok(())
            },
            Err(e) => {
                Err(RecoveryError::InvalidToken)
            }
        }
    }
}

// Helper function to generate a recovery token
fn generate_recovery_token() -> String {
    let mut rng = thread_rng();
    let token: u32 = rng.gen_range(100_000..=999_999);
    token.to_string()
}

// Helper function to mask a phone number
fn mask_phone_number(phone: &str) -> String {
    if phone.len() <= 6 {
        return phone.to_string();
    }
    
    let prefix = &phone[0..4];
    let suffix = &phone[phone.len() - 3..];
    format!("{}****{}", prefix, suffix)
}

/// Clean up expired recovery sessions
pub fn cleanup_expired_sessions() {
    let mut sessions = RECOVERY_SESSIONS.lock().unwrap();
    let now = Utc::now();
    
    // Remove sessions older than 1 hour
    sessions.retain(|_, session| {
        now.signed_duration_since(session.created_at) < Duration::hours(1)
    });
}

// Helper function to send SMS using Bonga SMS API
async fn send_sms(phone: &str, message: &str) -> Result<BongaSmsResponse, RecoveryError> {
    // Get API credentials from environment
    let api_client_id = std::env::var("BONGA_SMS_API_CLIENT_ID")
        .map_err(|_| RecoveryError::SmsError("Missing API client ID".into()))?;
    
    let api_key = std::env::var("BONGA_SMS_API_KEY")
        .map_err(|_| RecoveryError::SmsError("Missing API key".into()))?;
    
    let api_secret = std::env::var("BONGA_SMS_API_SECRET")
        .map_err(|_| RecoveryError::SmsError("Missing API secret".into()))?;
    
    let service_id = std::env::var("BONGA_SMS_SERVICE_ID")
        .unwrap_or_else(|_| "1".to_string());
    
    // Prepare the API request
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .text("apiClientID", api_client_id)
        .text("key", api_key)
        .text("secret", api_secret)
        .text("txtMessage", message.to_string())
        .text("MSISDN", phone.to_string())
        .text("serviceID", service_id);
    
    // Send the request
    let response = client.post("http://167.172.14.50:4002/v1/send-sms")
        .multipart(form)
        .send()
        .await?;
    
    // Parse the response
    let sms_response: BongaSmsResponse = response.json().await?;
    
    Ok(sms_response)
}

// Security question type
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
}