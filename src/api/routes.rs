// src/api/routes.rs
use actix_web::guard;
use super::handlers;
use actix_web::web;
use super::middleware::auth::TokenValidator;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    // Authentication routes
    cfg.service(
        web::scope("/auth")
            // POST: Unlock vault
            .route("/unlock", web::post().to(handlers::auth::unlock_vault))
            // OPTIONS: Unlock vault (for CORS preflight if needed)
            .route("/unlock", web::route()
                .guard(guard::Options())
                .to(handlers::auth::unlock_options))

            // GET: Check session status
            .route("/status", web::get().to(handlers::auth::check_status))
            // OPTIONS: Check session status
            .route("/status", web::route()
                .guard(guard::Options())
                .to(handlers::auth::status_options))

            // POST: Logout
            .route("/logout", web::post().to(handlers::auth::logout))
            // OPTIONS: Logout
            .route("/logout", web::route()
                .guard(guard::Options())
                .to(handlers::auth::logout_options))

            // POST: Change master password
            .route("/change-password", web::post().to(handlers::auth::change_password))
            // OPTIONS: Change master password
            .route("/change-password", web::route()
                .guard(guard::Options())
                .to(handlers::auth::change_password_options))
    );
    
    // Recovery routes
    cfg.service(
        web::scope("/recovery")
            .route("/status", web::get().to(handlers::recovery::get_status))
            .route("/setup/email", web::post().to(handlers::recovery::setup_email))
            .route("/setup/sms", web::post().to(handlers::recovery::setup_sms))
            .route("/setup/questions", web::post().to(handlers::recovery::setup_questions))
            .route("/disable", web::put().to(handlers::recovery::disable_recovery))
            .route("/initiate", web::post().to(handlers::recovery::initiate_recovery))
            .route("/verify/email", web::post().to(handlers::recovery::verify_email))
            .route("/verify/sms", web::post().to(handlers::recovery::verify_sms))
            .route("/verify/questions", web::post().to(handlers::recovery::verify_questions))
            .route("/reset", web::post().to(handlers::recovery::reset_password))
    );
    
    // Password routes (protected by token auth)
    // Password routes (protected by token auth)
    cfg.service(
        web::scope("/passwords")
            .service(
                web::scope("")
                    .wrap(TokenValidator)
                    .route("/count", web::get().to(handlers::passwords::count_passwords))
                    .route("", web::get().to(handlers::passwords::list_passwords))
                    .route("", web::post().to(handlers::passwords::add_password))
                    .route("/{id}", web::get().to(handlers::passwords::get_password))
                    .route("/{id}", web::put().to(handlers::passwords::update_password))
                    .route("/{id}", web::delete().to(handlers::passwords::delete_password))
            )
    );

    
    // Category routes (protected by token auth)
    cfg.service(
        web::scope("/categories")
            .wrap(TokenValidator)
            .route("", web::get().to(handlers::categories::list_categories))
            .route("", web::post().to(handlers::categories::add_category))
            .route("/{id}", web::put().to(handlers::categories::update_category))
            .route("/{id}", web::delete().to(handlers::categories::delete_category))
    );
    
    // Password generator (protected by token auth)
    cfg.service(
        web::scope("/generator")
            .wrap(TokenValidator)
            .route("/password", web::post().to(handlers::generator::generate_password))
            .route("/analysis/{pwd}", web::get().to(handlers::generator::analyze_password))
    );
    
    // Import routes (protected by token auth)
    cfg.service(
        web::scope("/import")
            .wrap(TokenValidator)
            .route("/firefox/profiles", web::get().to(handlers::import::list_firefox_profiles))
            .route("/firefox", web::post().to(handlers::import::import_firefox))
            .route("/chrome", web::post().to(handlers::import::import_chrome))
            .route("/edge", web::post().to(handlers::import::import_edge))
            .route("/csv", web::post().to(handlers::import::import_csv))
            .route("/vault", web::post().to(handlers::import::import_vault))
    );
    
    // Export routes (protected by token auth)
    cfg.service(
        web::scope("/export")
            .wrap(TokenValidator)
            // GET /export
            .route("", web::get().to(handlers::export::export_csv))
            // OPTIONS /export
            .route("", web::route()
                .guard(guard::Options())
                .to(handlers::export::export_options))

            // GET /export/vault
            .route("/vault", web::get().to(handlers::export::export_vault))
            // OPTIONS /export/vault
            .route("/vault", web::route()
                .guard(guard::Options())
                .to(handlers::export::export_options))
    );
    
    // Backup management (protected by token auth)
    cfg.service(
        web::scope("/backups")
            .wrap(TokenValidator)
            .route("", web::get().to(handlers::backups::list_backups))
            .route("", web::post().to(handlers::backups::create_backup))
            .route("/{id}", web::get().to(handlers::backups::get_backup_details))
            .route("/{id}/restore", web::post().to(handlers::backups::restore_backup))
            .route("/{id}", web::delete().to(handlers::backups::delete_backup))
    );
    
    // Privacy protection routes (protected by token auth)
    cfg.service(
        web::scope("/privacy")
            .wrap(TokenValidator)
            .route("/status", web::get().to(handlers::privacy::get_privacy_status))
            .route("/protection", web::get().to(handlers::privacy::get_protection_level))
            .route("/protection", web::put().to(handlers::privacy::set_protection_level))
            .route("/profiles", web::get().to(handlers::privacy::list_profiles))
            .route("/profiles/{name}", web::get().to(handlers::privacy::get_profile))
            .route("/profiles", web::post().to(handlers::privacy::create_profile))
            .route("/profiles/{name}", web::put().to(handlers::privacy::update_profile))
            .route("/profiles/{name}", web::delete().to(handlers::privacy::delete_profile))
            .route("/profiles/{name}/apply", web::post().to(handlers::privacy::apply_profile))
            .route("/harden/firefox", web::post().to(handlers::privacy::harden_firefox))
            .route("/status/firefox", web::get().to(handlers::privacy::check_firefox_status))
            .route("/status/firefox/detailed", web::get().to(handlers::privacy::get_firefox_detailed_status))
            .route("/firefox/hardening", web::get().to(handlers::privacy::check_firefox_hardening))
            .route("/clean", web::post().to(handlers::privacy::clean_privacy_data))
            .route("/fingerprint", web::get().to(handlers::privacy::get_fingerprint_settings))
            .route("/fingerprint", web::put().to(handlers::privacy::set_fingerprint_settings))
            .route("/fingerprint/test", web::get().to(handlers::privacy::test_fingerprinting))
            .route("/storage", web::get().to(handlers::privacy::get_storage_settings))
            .route("/storage", web::put().to(handlers::privacy::set_storage_settings))
            .route("/network", web::get().to(handlers::privacy::get_network_settings))
            .route("/network", web::put().to(handlers::privacy::set_network_settings))
            .route("/network/dns", web::post().to(handlers::privacy::configure_dns))
    );
    
    // System status and logs (protected by token auth)
    cfg.service(
        web::scope("/system")
            .wrap(TokenValidator)
            .route("/status", web::get().to(handlers::system::get_status))
            .route("/logs", web::get().to(handlers::system::get_logs))
            .route("/firejail/browser", web::post().to(handlers::system::launch_browser_sandbox))
            .route("/firejail/status", web::get().to(handlers::system::check_sandbox_status))
    );
    
    // OSINT tools (protected by token auth)
    cfg.service(
        web::scope("/tools")
            .wrap(TokenValidator)
            .route("/dork", web::post().to(handlers::tools::generate_dork))
    );
    
    // Educational content
    cfg.service(
        web::scope("/education")
            .wrap(TokenValidator)
            .route("/topics", web::get().to(handlers::education::list_topics))
            .route("/topics/{id}", web::get().to(handlers::education::get_topic))
    );
}