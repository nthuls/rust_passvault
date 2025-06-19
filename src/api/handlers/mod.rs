// src/api/handlers/mod.rs
pub mod auth;
pub mod recovery;
pub mod categories;
pub mod generator;
pub mod passwords;
pub mod import;
pub mod export;
pub mod tools;
pub mod education;
pub mod privacy;
pub mod system;  
pub mod backups; 
pub mod json_api;
pub use json_api::handle_json_api;
