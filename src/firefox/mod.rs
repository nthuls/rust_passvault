// src/firefox/mod.rs
pub mod profile;
pub mod credentials;
pub mod nss;

pub use profile::FirefoxProfiler;
pub use credentials::FirefoxCredentialManager;
