// src/api/mod.rs
use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use std::sync::Arc;
use crate::core::vault::Vault;
use utoipa::{OpenApi, Modify};
use utoipa_swagger_ui::SwaggerUi;
use utoipa_redoc::{Redoc, Servable};

// Add this section for SecurityAddon to add security schemes
#[derive(Default)]
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = &mut openapi.components {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

// This will hold our API documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        // Authentication endpoints
        crate::api::handlers::auth::unlock_vault,
        crate::api::handlers::auth::check_status,
        crate::api::handlers::auth::logout,
        crate::api::handlers::auth::change_password,
        
        // Password management endpoints
        crate::api::handlers::passwords::list_passwords,
        crate::api::handlers::passwords::add_password,
        crate::api::handlers::passwords::get_password,
        crate::api::handlers::passwords::update_password,
        crate::api::handlers::passwords::delete_password,
        crate::api::handlers::passwords::count_passwords,
        
        // Category endpoints
        crate::api::handlers::categories::list_categories,
        crate::api::handlers::categories::add_category,
        crate::api::handlers::categories::update_category,
        crate::api::handlers::categories::delete_category,
        
        // Generator endpoints
        crate::api::handlers::generator::generate_password,
        crate::api::handlers::generator::analyze_password,
        
        // Import endpoints
        crate::api::handlers::import::list_firefox_profiles,
        crate::api::handlers::import::import_firefox,
        crate::api::handlers::import::import_chrome,
        crate::api::handlers::import::import_edge,
        crate::api::handlers::import::import_csv,
        crate::api::handlers::import::import_vault,
        
        // Export endpoints
        crate::api::handlers::export::export_csv,
        crate::api::handlers::export::export_vault,
        
        // Backup endpoints
        crate::api::handlers::backups::list_backups,
        crate::api::handlers::backups::create_backup,
        crate::api::handlers::backups::get_backup_details,
        crate::api::handlers::backups::restore_backup,
        crate::api::handlers::backups::delete_backup,

        //education
        crate::api::handlers::education::list_topics,
        crate::api::handlers::education::get_topic,

        // Privacy endpoints
        crate::api::handlers::privacy::get_privacy_status,
        crate::api::handlers::privacy::set_protection_level,
        crate::api::handlers::privacy::list_profiles,
        crate::api::handlers::privacy::get_profile,
        crate::api::handlers::privacy::create_profile,
        crate::api::handlers::privacy::update_profile,
        crate::api::handlers::privacy::delete_profile,
        crate::api::handlers::privacy::apply_profile,
        crate::api::handlers::privacy::check_firefox_hardening,
        crate::api::handlers::privacy::harden_firefox,
        crate::api::handlers::privacy::clean_privacy_data,
        crate::api::handlers::privacy::get_fingerprint_settings,
        crate::api::handlers::privacy::set_fingerprint_settings,
        crate::api::handlers::privacy::test_fingerprinting,
        crate::api::handlers::privacy::get_storage_settings,
        crate::api::handlers::privacy::set_storage_settings,
        crate::api::handlers::privacy::get_network_settings,
        crate::api::handlers::privacy::set_network_settings,
        crate::api::handlers::privacy::configure_dns,
        
        // System endpoints
        crate::api::handlers::system::get_status,
        crate::api::handlers::system::get_logs,
        crate::api::handlers::system::launch_browser_sandbox,
        crate::api::handlers::system::check_sandbox_status
    ),
    components(
        schemas(
            // Request/response schemas
            crate::api::types::UnlockRequest,
            crate::api::types::TokenResponse,
            crate::api::types::StatusResponse,
            crate::api::types::SuccessResponse,
            crate::api::types::ChangePasswordRequest,
            crate::api::types::RecoveryStatus,
            crate::api::types::BackupMetadata,
            crate::api::types::BackupListResponse,
            crate::api::types::CreateBackupRequest,
            crate::api::types::RestoreBackupRequest,

            // ✅ Category-related
            crate::api::types::CategoryEntry,
            crate::api::types::CategoryListResponse,
            crate::api::types::AddCategoryRequest,
            crate::api::types::UpdateCategoryRequest,

            // New from Import
            crate::api::types::ImportFirefoxRequest,
            crate::api::types::ImportChromeRequest,
            crate::api::types::ImportEdgeRequest,
            crate::api::types::ImportVaultRequest,
            crate::api::types::ImportResponse,
            crate::api::types::ImportCSVRequest,

            // Education
            crate::api::types::TopicListResponse,
            crate::api::types::TopicContentResponse,

            // Password models
            crate::models::PasswordEntry,
            crate::api::types::PasswordListResponse,
            crate::api::types::AddPasswordRequest,
            crate::api::types::UpdatePasswordRequest,
            crate::api::types::PasswordGenerationRequest,
            crate::api::types::PasswordGenerationResponse,
            crate::api::types::PasswordAnalysisResponse,
            crate::api::types::CountResponse,

            // Privacy schemas
            crate::api::types::ProtectionLevelRequest,
            crate::api::types::ProtectionLevelResponse,
            crate::api::types::PrivacyStatusResponse,
            crate::api::types::ProfileListResponse,
            crate::api::types::CreateProfileRequest,
            crate::api::types::CleanPrivacyDataRequest,
            crate::api::types::FirefoxHardeningResponse,
            crate::api::types::FirefoxFingerprintingRequest,
            crate::api::types::FingerprintTestResponse,
            crate::privacy::levels::ProtectionLevel,
            crate::privacy::levels::PrivacySettings,
            crate::privacy::fingerprint::FingerprintSettings,
            crate::privacy::storage::StorageSettings,
            crate::privacy::network::NetworkSettings,
            crate::privacy::browsers::firefox::FirefoxSettings,
            crate::privacy::PrivacyStatus,
            crate::privacy::network::dns::DnsSettings,
            

            // System schemas
            crate::system::SystemStatus,
            crate::system::firejail::FirejailStatus,
            crate::system::firejail::LaunchBrowserRequest,
            crate::system::firejail::ActiveBrowser,
            crate::system::firejail::BrowserInfo,
            crate::logging::LogEntry,
            crate::logging::LogLevel,
            crate::logging::LogFilter


        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Authentication", description = "Authentication and session management endpoints"),
        (name = "Passwords", description = "Password management endpoints"),
        (name = "Categories", description = "Category management endpoints"),
        (name = "Generator", description = "Password generation endpoints"),
        (name = "Import", description = "Import endpoints for various sources"),
        (name = "Export", description = "Export endpoints for data portability"),
        (name = "Backups", description = "Backup management endpoints"),
        (name = "Privacy", description = "Privacy protection endpoints"),
        (name = "System", description = "System status and utilities")
    ),
    info(
        title = "RustVault API",
        version = "0.1.0",
        description = "Secure Password Manager & Privacy Shield API",
        license(name = "MIT"),
        contact(
            name = "SecureVault Team",
            email = "contact@securevault.example.com",
            url = "https://securevault.example.com"
        )
    )
)]
struct ApiDoc;

pub async fn start_server(vault: Arc<Vault>, port: u16) -> std::io::Result<()> {
    log::info!("Starting RustVault API server on port {}", port);

    // Clone the vault once outside the closure to avoid borrow checker issues
    let vault_data = web::Data::new(vault);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin() // Allow requests from any origin during development
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                "Authorization",
                "Content-Type",
                "Accept",
                "X-Requested-With",
            ])
            .supports_credentials() // Important for authentication requests
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(vault_data.clone())
            // Add Swagger UI
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi())
            )
            // Add Redoc
            .service(Redoc::with_url("/redoc", ApiDoc::openapi()))
            // Configure your regular API routes
            .configure(routes::configure_routes)
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

pub mod types;
pub mod routes;
pub mod handlers;
pub mod middleware;
pub mod utils;