use clap::Parser;
use std::error::Error;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::path::Path;
use std::io;
use actix_web::web;

mod cli;
mod api;
mod core;
mod utils;
mod models;
mod crypto;
mod db;
mod firefox;
mod importers;
mod generators;
mod recovery;
mod system;
mod privacy;
mod tools;
mod backups;
mod education;
mod logging;

use crate::cli::Args;
use crate::db::Database;
use crate::core::config::Config;
pub use crate::core::vault::Vault;

// Helper function to print debug information
fn debug_print(message: &str) {
    // Print to both console and log
    println!("DEBUG: {}", message);
    log::debug!("{}", message);
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Set env var to show more detailed Actix errors
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "debug,actix_web=debug");
    
    println!("===============================================");
    println!("STARTING APPLICATION WITH DEBUG MODE ENABLED");
    println!("===============================================");
    
    // Load environment variables
    if Path::new(".env").exists() {
        dotenvy::dotenv().ok();
        debug_print("Loaded .env file");
    } else {
        debug_print("No .env file found");
    }

    let args = Args::parse();
    debug_print(&format!("Command line args: {:?}", args));
    
    let config = Config::load();
    debug_print(&format!("Loaded config: {:?}", config));

    // Ensure logs directory exists
    let logs_dir = Path::new("logs");
    if !logs_dir.exists() {
        debug_print("Creating logs directory");
        std::fs::create_dir_all(logs_dir)?;
    }

    // Configure logging to output to both file and console
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug) // Force debug level
        .format_timestamp_secs()
        .format_module_path(true) // Show module path for better tracing
        .format_target(true)      // Show target for better tracing
        // Clone the logger to output to both console and file
        .target(env_logger::Target::Pipe(Box::new(
            std::fs::File::create(logs_dir.join("app.log"))?
        )))
        .init();

    log::info!("🔒 Starting SecureVault - Password Manager & Privacy Shield");
    debug_print("Initializing application...");

    let db_url = config.get_database_url();
    println!("Connecting to database: {}", db_url);

    debug_print("Attempting database connection...");
    let db = match db::init_db(&args.db).await {
        Ok(db) => {
            println!("✅ Database connection successful");
            debug_print("Database connection established successfully");
            db
        },
        Err(e) => {
            eprintln!("❌ Database connection failed: {e}");
            debug_print(&format!("Database connection error details: {:?}", e));
            eprintln!("Troubleshooting:");
            eprintln!("• Is your DB server running?");
            eprintln!("• Are credentials correct?");
            eprintln!("• For SQLite: does the path exist?");
            eprintln!("• For Postgres: create the DB if needed: `createdb securevault -U postgres`");
            eprintln!("• Use --db or set DATABASE_URL in `.env`");
            return Ok(());
        }
    };

    debug_print("Setting up signal handlers");
    let should_exit = Arc::new(AtomicBool::new(false));

    {
        let should_exit = Arc::clone(&should_exit);
        ctrlc::set_handler(move || {
            log::info!("🔴 Ctrl+C received. Initiating shutdown...");
            should_exit.store(true, Ordering::SeqCst);
            println!("\n🧹 Shutdown complete. Goodbye!");
            std::process::exit(0);
        }).expect("Failed to set Ctrl+C handler");
    }

    debug_print("Creating vault and service instances");
    let db = Arc::new(db);
    let vault = Arc::new(Vault::new(Arc::clone(&db)));
    let vault_data = web::Data::new(Arc::clone(&vault)); // 👈 wrap in Data

    let api_port = args.api_port.unwrap_or(5000);
    debug_print(&format!("API will run on port: {}", api_port));

    // Run recovery cleanup task every 5 minutes
    debug_print("Starting recovery cleanup task");
    tokio::spawn(async {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            debug_print("Running scheduled cleanup of expired sessions");
            recovery::cleanup_expired_sessions();
        }
    });

    // API-only mode (blocks forever)
    if args.api_only {
        log::info!("🔒 API-only mode active. CLI interface disabled.");
        debug_print("Running in API-only mode");
        println!("===============================================");
        println!("STARTING API SERVER (API-ONLY MODE)");
        println!("===============================================");
        return api::start_server(vault, api_port).await
            .map_err(|e| {
                log::error!("API server failed: {}", e);
                eprintln!("API SERVER ERROR: {:?}", e);
                println!("API server failed with error: {:?}", e);
                io::Error::new(io::ErrorKind::Other, e.to_string())
            });
    }

    // Start API server in background (using a separate thread for Actix)
    {
        debug_print("Starting API server in background thread");
        let vault_clone = Arc::clone(&vault);
        
        // Use a separate thread with its own runtime for Actix Web
        std::thread::spawn(move || {
            println!("===============================================");
            println!("STARTING API SERVER (BACKGROUND MODE)");
            println!("===============================================");
            
            match tokio::runtime::Runtime::new() {
                Ok(rt) => {
                    debug_print("Created new tokio runtime for API server");
                    rt.block_on(async {
                        debug_print("API server starting...");
                        match api::start_server(vault_clone, api_port).await {
                            Ok(_) => {
                                debug_print("API server completed successfully");
                                log::info!("API server shut down gracefully");
                            }
                            Err(e) => {
                                let error_msg = format!("API server error: {:?}", e);
                                println!("ERROR: {}", error_msg);
                                log::error!("{}", error_msg);
                            }
                        }
                    });
                }
                Err(e) => {
                    let error_msg = format!("Failed to create tokio runtime: {:?}", e);
                    println!("ERROR: {}", error_msg);
                    log::error!("{}", error_msg);
                }
            }
        });
        println!("🚀 API server started on port {}", api_port);
    }

    // JSON API mode
    if args.json {
        debug_print("Running in JSON API mode");
        api::handlers::handle_json_api(args, (*db).clone()).await.map_err(|e| {
            let error_msg = format!("JSON API handler failed: {:?}", e);
            println!("ERROR: {}", error_msg);
            log::error!("{}", error_msg);
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        return Ok(());
    }

    // CLI interactive menu
    debug_print("Launching interactive CLI menu");
    cli::menu::run_cli_menu((*db).clone(), should_exit).await.map_err(|e| {
        let error_msg = format!("CLI menu error: {:?}", e);
        println!("ERROR: {}", error_msg);
        log::error!("{}", error_msg);
        io::Error::new(io::ErrorKind::Other, e.to_string())
    })?;

    debug_print("Application shutting down");
    log::info!("🔒 Closing database connections...");
    log::info!("✅ SecureVault shutdown complete.");

    Ok(())
}