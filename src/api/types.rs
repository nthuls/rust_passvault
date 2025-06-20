// src/api/types.rs
use serde::{Serialize, Deserialize};
use utoipa::ToSchema;
use utoipa::IntoParams;
use std::collections::HashMap;

// Authentication requests and responses
#[derive(Serialize, Deserialize, ToSchema)]
pub struct UnlockRequest {
    /// Master password for the vault
    pub password: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// JWT token for authenticated requests (only present on success)
    pub token: Option<String>,
    /// Error message (only present on failure)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Whether the user is authenticated
    pub authenticated: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SuccessResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Success message (only present on success)
    pub message: Option<String>,
    /// Error message (only present on failure)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current master password
    pub current_password: String,
    /// New master password to set
    pub new_password: String,
}

// Recovery types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RecoveryStatus {
    /// Whether the operation was successful
    pub success: bool,
    /// Whether email recovery is enabled
    pub email_recovery_enabled: bool,
    /// Whether SMS recovery is enabled
    pub sms_recovery_enabled: bool,
    /// Whether security questions recovery is enabled
    pub security_questions_enabled: bool,
    /// Recovery email address (if configured)
    pub recovery_email: Option<String>,
    /// Masked recovery phone number (e.g. "+2547****123")
    pub recovery_phone_masked: Option<String>,
    /// Number of configured security questions
    pub security_questions_count: usize,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct EmailSetupRequest {
    /// Email address for recovery
    pub email: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SmsSetupRequest {
    /// Phone number for recovery (format: +254XXXXXXXXX)
    pub phone: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecurityQuestion {
    /// Security question text
    pub question: String,
    /// Answer to the security question
    pub answer: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecurityQuestionsSetupRequest {
    /// List of security questions and answers
    pub questions: Vec<SecurityQuestion>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RecoveryInitiateRequest {
    /// Recovery method ("email" or "sms")
    pub method: String,
    /// Email or phone number to send recovery code to
    pub identifier: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct VerifyTokenRequest {
    /// Recovery token received via email or SMS
    pub token: String,
    /// Recovery session ID
    pub recovery_id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct VerifyQuestionsRequest {
    /// Answers to security questions
    pub answers: Vec<String>,
    /// Recovery session ID
    pub recovery_id: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    /// New master password
    pub new_password: String,
    /// Recovery session ID
    pub recovery_id: String,
}

// Bonga SMS API response
#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct BongaSmsResponse {
    /// Status code
    pub status: i32,
    /// Status message
    pub status_message: String,
    /// Unique message ID
    pub unique_id: Option<String>,
    /// Remaining credits
    pub credits: Option<i32>,
}

// Category-related types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct CategoryEntry {
    /// Category ID
    pub id: String,
    /// Category name
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CategoryListResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// List of categories
    pub categories: Vec<CategoryEntry>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddCategoryRequest {
    /// Name of the category to add
    pub name: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdateCategoryRequest {
    /// New name for the category
    pub name: String,
}

// Password-related types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordEntry {
    /// Password entry ID
    pub id: String,
    /// Website or application name
    pub site: String,
    /// Username or email
    pub username: String,
    /// Password value (only present when explicitly requested)
    pub password: Option<String>,
    /// Additional notes
    pub notes: Option<String>,
    /// List of category names this password belongs to
    pub categories: Vec<String>,
    /// Creation timestamp
    pub created_at: String,
    /// Last update timestamp
    pub updated_at: String,
    /// Password strength score (0-100)
    pub strength: Option<u8>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordListResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// List of password entries
    pub passwords: Vec<PasswordEntry>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AddPasswordRequest {
    pub site: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub categories: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct UpdatePasswordRequest {
    pub site: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
    pub categories: Option<Vec<String>>,
}

/// Response type for count endpoints
#[derive(Serialize, ToSchema)]
pub struct CountResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Total number of stored passwords
    pub count: i64,
}


// Password generation types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordGenerationRequest {
    /// Password length (default: 16)
    pub length: Option<usize>,
    /// Include uppercase letters (default: true)
    pub include_uppercase: Option<bool>,
    /// Include lowercase letters (default: true)
    pub include_lowercase: Option<bool>,
    /// Include numbers (default: true)
    pub include_numbers: Option<bool>,
    /// Include symbols (default: true)
    pub include_symbols: Option<bool>,
    /// Exclude similar characters (default: false)
    pub exclude_similar: Option<bool>,
    /// Generate a memorable password (default: false)
    pub memorable: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordGenerationResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Generated password
    pub password: Option<String>,
    /// Password strength score (0-100)
    pub strength: Option<u8>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PasswordAnalysisResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Password strength score (0-100)
    pub strength: u8,
    /// Feedback and suggestions for improvement
    pub feedback: Vec<String>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

// Import-related types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxProfileEntry {
    /// Profile name
    pub name: String,
    /// Profile path on disk
    pub path: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxProfileListResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// List of Firefox profiles
    pub profiles: Vec<FirefoxProfileEntry>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ImportFirefoxRequest {
    /// Path to Firefox profile (optional, uses default if not specified)
    pub profile_path: Option<String>,
    /// Firefox master password (if profile is protected)
    pub master_password: Option<String>,
    /// Category to assign to imported passwords
    pub category: Option<String>,
    /// Check if we want to update an exixting passwd
    pub update_existing: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ImportChromeRequest {
    /// Path to Chrome profile (optional, uses default if not specified)
    pub profile_path: Option<String>,
    /// Category to assign to imported passwords
    pub category: Option<String>,
    /// Check if we want to update an exixting passwd
    pub update_existing: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ImportEdgeRequest {
    /// Path to Edge profile (optional, uses default if not specified)
    pub profile_path: Option<String>,
    /// Category to assign to imported passwords
    pub category: Option<String>,
    /// Check if we want to update an exixting passwd
    pub update_existing: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ImportResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Total number of password entries processed (added + updated)
    pub count: usize,
    /// Number of new password entries added
    pub added_count: Option<usize>,
    /// Number of existing password entries updated
    pub updated_count: Option<usize>,
    /// Success message
    pub message: Option<String>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

// Export-related types
#[derive(Serialize, Deserialize, ToSchema, IntoParams, Debug)]
pub struct ExportRequest {
    /// Include actual password values (default: false)
    pub include_passwords: Option<bool>,
    /// Include notes (default: true)
    pub include_notes: Option<bool>,
    /// Password to encrypt the export (for vault format)
    pub password: Option<String>,
}

// Backup Metadata
#[derive(Serialize, Deserialize, ToSchema)]
pub struct BackupMetadata {
    /// Backup ID
    pub id: String,
    /// Backup filename
    pub filename: String,
    /// Backup creation timestamp
    pub created_at: String,
    /// Backup description
    pub description: Option<String>,
    /// Backup file size in bytes
    pub size_bytes: u64,
    /// Number of passwords in the backup
    pub password_count: usize,
    /// Number of categories in the backup
    pub category_count: usize,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct BackupListResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// List of backups
    pub backups: Vec<BackupMetadata>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateBackupRequest {
    /// Backup description
    pub description: Option<String>,
    /// Optional separate password for the backup
    pub backup_password: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct RestoreBackupRequest {
    /// Backup ID to restore
    pub id: String,
    /// Backup password (if separate password was used)
    pub backup_password: Option<String>,
}

// OSINT Tools Types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct DorkRequest {
    /// Search type ("site", "filetype", "intext", "inurl", etc.)
    pub search_type: String,
    /// Keywords to search for
    pub keywords: Vec<String>,
    /// Terms to exclude from search
    pub exclude_terms: Option<Vec<String>>,
    /// Specific sites to search within
    pub site_restrictions: Option<Vec<String>>,
    /// Specific file types to search for
    pub file_types: Option<Vec<String>>,
    /// Date range for search results
    pub date_range: Option<DateRange>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct DateRange {
    /// Start date (Format: YYYY-MM-DD)
    pub start_date: String,
    /// End date (Format: YYYY-MM-DD)
    pub end_date: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct DorkResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Generated dork query
    pub dork_query: Option<String>,
    /// Explanation of the dork query
    pub explanation: Option<String>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

// Education Content Types
#[derive(Serialize, Deserialize, ToSchema)]
pub struct EducationTopic {
    /// Topic ID
    pub id: String,
    /// Topic title
    pub title: String,
    /// Topic description
    pub description: String,
    /// Topic category
    pub category: String,
    /// Topic difficulty level ("beginner", "intermediate", "advanced")
    pub difficulty: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TopicContent {
    /// Topic ID
    pub id: String,
    /// Topic title
    pub title: String,
    /// Topic content in Markdown format
    pub content: String,
    /// Topic category
    pub category: String,
    /// Topic difficulty level
    pub difficulty: String,
    /// Related topic IDs
    pub related_topics: Vec<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TopicListResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// List of education topics
    pub topics: Vec<EducationTopic>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct TopicContentResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Topic content
    pub topic: Option<TopicContent>,
    /// Error message (if operation failed)
    pub error: Option<String>,
}

/// Request to import a vault file
#[derive(Serialize, Deserialize, ToSchema)]
pub struct ImportVaultRequest {
    /// Encrypted vault file
    #[schema(format = "binary")]
    pub file: String, // This is a placeholder for the file upload
    
    /// Password to decrypt the vault (if different from master password)
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct ImportCSVRequest {
    /// Raw CSV data (as text)
    pub csv_data: String,

    /// Optional override for category
    pub category: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ProtectionLevelRequest {
    pub level: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ProtectionLevelResponse {
    pub success: bool,
    pub level: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PrivacyStatusResponse {
    pub success: bool,
    pub status: crate::privacy::PrivacyStatus,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ProfileListResponse {
    pub success: bool,
    pub profiles: Vec<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreateProfileRequest {
    pub name: String,
    pub description: String,
    pub level: String,
    pub settings: Option<crate::privacy::levels::PrivacySettings>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CleanPrivacyDataRequest {
    pub clear_cookies: Option<bool>,
    pub clear_history: Option<bool>,
    pub clear_cache: Option<bool>,
    pub clear_local_storage: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxHardeningResponse {
    pub success: bool,
    pub applied_settings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxFingerprintingRequest {
    pub canvas_protection: Option<bool>,
    pub webgl_protection: Option<bool>,
    pub audio_protection: Option<bool>,
    pub font_protection: Option<bool>,
    pub hardware_protection: Option<bool>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FingerprintTestResponse {
    pub success: bool,
    pub fingerprint_level: String,
    pub tests: HashMap<String, bool>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct FirefoxStatusResponse {
    pub success: bool,
    pub status: Option<crate::privacy::browsers::firefox::FirefoxStatus>,
    pub error: Option<String>,
}