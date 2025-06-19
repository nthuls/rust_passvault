# RustVault API Implementation Plan

## Overview

This document outlines the plan for implementing the API endpoints needed for RustVault's backend, which will support all the features described in the requirements. The API will be built with Actix Web, use JWT for authentication, and provide REST endpoints returning JSON.

## Core Architecture

```
+----------------------+      +--------------------+
|                      |      |                    |
|  Flask Web Frontend  |<---->|  Rust API Layer    |
|                      |      |                    |
+----------------------+      +--------------------+
                                       |
                                       v
                              +--------------------+
                              |                    |
                              |  Existing Core     |
                              |  Vault Logic       |
                              |                    |
                              +--------------------+
                                       |
                                       v
                              +--------------------+
                              |                    |
                              |  Database Layer    |
                              |  (SQLite/Postgres) |
                              |                    |
                              +--------------------+
```

## API Endpoint Groups

### 1. Authentication & Account Management
- **Authentication**: Vault unlocking, session management
- **Recovery**: Email/SMS verification, security questions
- **Account Settings**: Master password change, recovery options

### 2. Password Management
- **Passwords CRUD**: Create, read, update, delete password entries
- **Categories**: Manage password categories
- **Search/Filter**: Find passwords by criteria
- **Password Generation**: Create strong passwords

### 3. Import/Export
- **Browser Import**: Firefox import (initial), Chrome/Edge (future)
- **File Import/Export**: CSV, encrypted vault format
- **Backup Management**: Create, list, restore backups

### 4. Privacy Features
- **Protection Levels**: Basic, Standard, Strict, Custom
- **Fingerprinting Protection**: Canvas, WebGL, Audio, Font
- **Storage Protection**: Cookies, LocalStorage, Cache
- **Network Protection**: DNS, Referer, User-Agent
- **Firefox Hardening**: Apply privacy settings

### 5. System & Tools
- **Status & Monitoring**: Vault status, statistics
- **Browser Isolation**: Firejail integration
- **OSINT Tools**: Google Dork builder
- **Security Education**: Educational content delivery

## Detailed API Endpoints

### 1. Authentication & Account Management

#### Core Authentication
```
POST /api/v1/auth/unlock           # Unlock vault with master password
GET  /api/v1/auth/status           # Check authentication status
POST /api/v1/auth/logout           # Lock vault / invalidate token
POST /api/v1/auth/change-password  # Change master password
```

#### Recovery Setup
```
GET  /api/v1/recovery/status             # Get recovery settings status
POST /api/v1/recovery/setup/email        # Set up email recovery
POST /api/v1/recovery/setup/sms          # Set up SMS recovery (Bonga SMS)
POST /api/v1/recovery/setup/questions    # Set up security questions
PUT  /api/v1/recovery/disable            # Disable recovery options
```

#### Recovery Process
```
POST /api/v1/recovery/initiate           # Start recovery process
POST /api/v1/recovery/verify/email       # Verify email token
POST /api/v1/recovery/verify/sms         # Verify SMS token
POST /api/v1/recovery/verify/questions   # Verify security questions
POST /api/v1/recovery/reset              # Reset master password
```

### 2. Password Management

#### Password CRUD
```
GET    /api/v1/passwords                 # List all passwords
POST   /api/v1/passwords                 # Add new password
GET    /api/v1/passwords/{id}            # Get specific password
PUT    /api/v1/passwords/{id}            # Update password
DELETE /api/v1/passwords/{id}            # Delete password
```

#### Categories
```
GET    /api/v1/categories                # List all categories
POST   /api/v1/categories                # Create new category
PUT    /api/v1/categories/{id}           # Update category
DELETE /api/v1/categories/{id}           # Delete category
```

#### Password Generation
```
POST   /api/v1/generator/password        # Generate password
GET    /api/v1/generator/analysis/{pwd}  # Analyze password strength
```

### 3. Import/Export

#### Browser Import
```
GET    /api/v1/import/firefox/profiles   # List Firefox profiles
POST   /api/v1/import/firefox            # Import from Firefox
POST   /api/v1/import/chrome             # Import from Chrome (future)
POST   /api/v1/import/edge               # Import from Edge (future)
```

#### File Import/Export
```
POST   /api/v1/import/csv                # Import from CSV
GET    /api/v1/export/csv                # Export to CSV
GET    /api/v1/export/vault              # Export encrypted vault file
```

#### Backup Management
```
GET    /api/v1/backups                   # List backups
POST   /api/v1/backups                   # Create new backup
GET    /api/v1/backups/{id}              # Get backup details
POST   /api/v1/backups/{id}/restore      # Restore from backup
DELETE /api/v1/backups/{id}              # Delete backup
```

### 4. Privacy Features

#### Protection Management
```
GET    /api/v1/privacy/protection        # Get current protection level
PUT    /api/v1/privacy/protection        # Set protection level
GET    /api/v1/privacy/profiles          # List available profiles
GET    /api/v1/privacy/profiles/{name}   # Get specific profile
POST   /api/v1/privacy/profiles          # Create custom profile
PUT    /api/v1/privacy/profiles/{name}   # Update profile
```

#### Browser Protection
```
POST   /api/v1/privacy/harden/firefox    # Apply Firefox hardening
GET    /api/v1/privacy/status/firefox    # Check Firefox status
POST   /api/v1/privacy/clean             # Clean privacy data
```

#### Fingerprinting Protection
```
GET    /api/v1/privacy/fingerprint       # Get fingerprint protection status
PUT    /api/v1/privacy/fingerprint       # Configure fingerprint protection
```

#### Storage Protection
```
GET    /api/v1/privacy/storage           # Get storage protection settings
PUT    /api/v1/privacy/storage           # Configure storage protection
```

#### Network Protection
```
GET    /api/v1/privacy/network           # Get network protection settings
PUT    /api/v1/privacy/network           # Configure network protection
POST   /api/v1/privacy/network/dns       # Configure DNS protection
```

### 5. System & Tools

#### System Status
```
GET    /api/v1/system/status             # Get system status
GET    /api/v1/system/logs               # Get system logs
```

#### OSINT Tools
```
POST   /api/v1/tools/dork                # Generate Google Dork
```

#### Firejail Integration
```
POST   /api/v1/system/firejail/browser   # Launch browser in sandbox
GET    /api/v1/system/firejail/status    # Check sandboxing status
```

#### Educational Content
```
GET    /api/v1/education/topics          # List educational topics
GET    /api/v1/education/topics/{id}     # Get educational content
```

## Implementation Priorities

We'll implement these endpoints in phases to deliver value incrementally:

### Phase 1: Core Password Management (Essential)
- Authentication endpoints
- Basic password CRUD operations
- Category management
- Password generation

### Phase 2: Import/Export (High Priority)
- Firefox import
- CSV import/export
- Backup management

### Phase 3: Privacy Features (Medium Priority)
- Protection levels
- Firefox hardening
- Fingerprinting protection

### Phase 4: Recovery & Tools (Lower Priority)
- Recovery setup and process
- OSINT tools
- Educational content

### Phase 5: Advanced Protection (Final Phase)
- Firejail integration
- Network protection
- Storage protection

## Data Models

### Authentication
```rust
struct UnlockRequest {
    password: String,
}

struct TokenResponse {
    success: bool,
    token: Option<String>,
    error: Option<String>,
}
```

### Password Management
```rust
struct PasswordEntry {
    id: String,
    site: String,
    username: String,
    password: String, // Only sent when specifically requested
    notes: Option<String>,
    categories: Vec<String>,
    created_at: String,
    updated_at: String,
}

struct Category {
    id: String,
    name: String,
}

struct PasswordGenerationOptions {
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
    exclude_similar: bool,
    memorable: bool,
}
```

### Privacy Features
```rust
enum ProtectionLevel {
    Basic,
    Standard, 
    Strict,
    Custom,
}

struct PrivacyProfile {
    name: String,
    description: String,
    protection_level: ProtectionLevel,
    fingerprint_settings: FingerprintSettings,
    storage_settings: StorageSettings,
    network_settings: NetworkSettings,
}

struct FingerprintSettings {
    canvas_protection: bool,
    webgl_protection: bool,
    audio_protection: bool,
    font_protection: bool,
}

struct StorageSettings {
    cookie_management: bool,
    localstorage_clearing: bool,
    cache_management: bool,
    evercookie_mitigation: bool,
}

struct NetworkSettings {
    dns_privacy: bool,
    referer_control: bool,
    user_agent_management: bool,
    tls_fingerprinting_mitigation: bool,
}
```

### Recovery
```rust
struct RecoveryStatus {
    email_recovery_enabled: bool,
    sms_recovery_enabled: bool,
    security_questions_enabled: bool,
    recovery_email: Option<String>,
    recovery_phone: Option<String>,
    security_questions_count: usize,
}

struct EmailSetupRequest {
    email: String,
}

struct SmsSetupRequest {
    phone: String, // Format: +254XXXXXXXXX
}

struct SecurityQuestionSetup {
    questions: Vec<SecurityQuestion>,
}

struct SecurityQuestion {
    question: String,
    answer: String,
}

struct RecoveryInitiateRequest {
    method: String, // "email" or "sms"
}

struct VerifyTokenRequest {
    token: String,
}

struct VerifyQuestionsRequest {
    answers: Vec<String>,
}

struct ResetPasswordRequest {
    new_password: String,
    token: String,
}
```

## Next Steps

1. **Environment Setup**
   - Set up Actix Web
   - Configure JWT middleware
   - Set up OpenAPI documentation

2. **Implement Phase 1 Endpoints**
   - Authentication endpoints
   - Password CRUD operations
   - Category management
   - Password generation

3. **Testing**
   - Create unit tests for each endpoint
   - Test with Postman/curl
   - Validate with Swagger UI

4. **Documentation**
   - Document all implemented endpoints
   - Create usage examples

5. **Move to Phase 2**
   - Start implementing import/export functionality

# Integration with Existing RustVault Code

Based on the project files you've shared, we need to plan how to integrate the new API endpoints with your existing code. Here's an analysis of your current structure and how we can extend it.

## Current Structure Analysis

Your project already has several well-organized components:

### Core Functionality
- **Crypto Module** (`crypto.rs`): Strong encryption with AES-256-GCM and Argon2id
- **Database Layer** (`db/mod.rs`, `db/postgres.rs`, `db/sqlite.rs`): Abstraction for both SQLite and PostgreSQL
- **Models** (`models.rs`): Data structures for passwords, categories, etc.
- **Core Vault** (`core/vault.rs`): Main business logic for the vault
- **Auth Management** (`core/auth.rs`): Authentication and session handling

### Import/Export
- **Firefox Import** (`importers/firefox.rs`, `firefox/` modules): Firefox credentials import
- **CSV Import/Export** (`importers/csv.rs`): CSV file handling

### CLI Interface
- **CLI Menu** (`cli/menu.rs`): Interactive TUI menu
- **CLI Commands** (`cli/commands.rs`): Command definitions
- **CLI Handlers** (`cli/handlers.rs`): Command execution

### Other Features
- **Password Generation** (`generators/password.rs`): Password creation
- **Utilities** (`utils/io.rs`, `utils/format.rs`): Helper functions

## Integration Strategy

Here's how we'll integrate our new API with your existing code:

### 1. Create API Module Structure

Add a new `api` module that mirrors your CLI structure:

```
src/api/
├── mod.rs                # Module exports
├── routes.rs             # API route definitions
├── handlers/             # API request handlers
│   ├── mod.rs
│   ├── auth.rs           # Authentication handlers
│   ├── passwords.rs      # Password management handlers
│   ├── ...
├── middleware/           # API middleware
│   ├── mod.rs
│   ├── auth.rs           # JWT authentication
│   ├── error.rs          # Error handling
├── types.rs              # Request/response types
```

### 2. Reuse Existing Functionality

The API handlers will delegate to your existing core functionality:

```rust
// Example: API handler for listing passwords
pub async fn list_passwords(
    vault: web::Data<Arc<Vault>>,
    token: web::ReqData<String>,
) -> Result<HttpResponse, Error> {
    // Leverage existing vault functionality
    match vault.get_all_passwords(&token).await {
        Ok(passwords) => {
            // Transform internal models to API response
            let password_responses: Vec<PasswordResponse> = 
                passwords.into_iter().map(PasswordResponse::from).collect();
                
            Ok(HttpResponse::Ok().json(PasswordListResponse {
                success: true,
                passwords: password_responses,
                error: None,
            }))
        },
        Err(e) => {
            // Handle error
            Ok(HttpResponse::Unauthorized().json(PasswordListResponse {
                success: false,
                passwords: vec![],
                error: Some(e.to_string()),
            }))
        }
    }
}
```

### 3. Extend Core Functionality

For new features not in the existing codebase:

1. **Privacy Module**: Create a new `privacy` module with proper abstractions:
   ```
   src/privacy/
   ├── mod.rs
   ├── profiles.rs          # Privacy profiles management
   ├── firefox.rs           # Firefox hardening implementation
   ├── fingerprint.rs       # Fingerprinting protection
   ├── storage.rs           # Storage protection
   ├── network.rs           # Network protection
   ```

2. **Recovery Module**: Add recovery functionality:
   ```
   src/recovery/
   ├── mod.rs
   ├── email.rs             # Email verification
   ├── sms.rs               # SMS (Bonga) integration
   ├── questions.rs         # Security questions logic
   ```

3. **System Module**: For system-level operations:
   ```
   src/system/
   ├── mod.rs
   ├── firejail.rs          # Firejail integration
   ├── backup.rs            # Backup management
   ├── status.rs            # System status reporting
   ```

### 4. JWT Authentication Adaptation

Your current `auth.rs` uses a custom token implementation. We'll extend it to support JWT:

```rust
// In src/core/auth.rs
impl AuthManager {
    // Existing methods...
    
    // New method for JWT token generation
    pub fn generate_jwt(&self, session_id: &str) -> Result<String, AuthError> {
        let claims = Claims {
            sub: "user".to_string(),
            exp: (Utc::now() + self.session_duration).timestamp(),
            sid: session_id.to_string(),
        };
        
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;
        
        Ok(token)
    }
    
    // New method for JWT validation
    pub fn validate_jwt(&self, token: &str) -> Result<String, AuthError> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )?;
        
        let claims = token_data.claims;
        
        if claims.exp < Utc::now().timestamp() {
            return Err(AuthError::SessionExpired);
        }
        
        Ok(claims.sid)
    }
}
```

### 5. Main Application Entry Point

Modify `main.rs` to conditionally start the API server:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Existing initialization code...
    
    // Create a shared vault instance
    let vault = Arc::new(Vault::new(&db));
    
    // Check if we should run the API server
    if !args.no_api {
        // Start API server in a separate thread
        let vault_clone = Arc::clone(&vault);
        tokio::spawn(async move {
            api::start_server(vault_clone, args.api_port).await;
        });
        
        println!("🚀 API server started on port {}", args.api_port);
    }
    
    // Continue with existing CLI logic if not in API-only mode
    if !args.api_only {
        cli::menu::run_cli_menu(db, should_exit).await?;
    } else {
        // Wait indefinitely while API server runs
        tokio::signal::ctrl_c().await?;
        println!("Shutting down...");
    }
    
    Ok(())
}
```

## Required New Dependencies

Add these to your `Cargo.toml`:

```toml
[dependencies]
# Existing dependencies...

# API Framework
actix-web = "4.3.1"
actix-cors = "0.6.4"
actix-rt = "2.8.0"

# JWT Authentication
jsonwebtoken = "8.3.0"

# API Documentation
utoipa = "3.3.0"
utoipa-swagger-ui = "3.1.3"

# File Upload
actix-multipart = "0.6.0"

# SMS Integration (for Bonga SMS)
reqwest = { version = "0.11", features = ["json"] }

# Email (if needed)
lettre = "0.10"
```

## New CLI Arguments

Add these to your existing CLI arguments:

```rust
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    // Existing arguments...
    
    /// Start the API server
    #[arg(long)]
    pub api_only: bool,
    
    /// Skip starting the API server
    #[arg(long)]
    pub no_api: bool,
    
    /// API server port
    #[arg(long, default_value = "5000")]
    pub api_port: u16,
}
```

## Next Steps

1. **Create Foundational Structure**:
   - Add API module and basic structure
   - Set up Actix Web with basic routing
   
2. **Implement Authentication**:
   - Extend AuthManager with JWT support
   - Create authentication middleware
   
3. **Core Password Management**:
   - Implement password CRUD endpoints
   - Adapt existing functionality to API handlers
   
4. **Progressive Enhancement**:
   - Add import/export functionality
   - Add privacy features
   - Implement recovery process
   - Add advanced features

This integration strategy ensures we build on your existing, solid foundation while adding the API capabilities needed for the web frontend.

# Privacy Features Implementation Plan

This document outlines how we'll implement the privacy features mentioned in the requirements, focusing on the backend implementation.

## 1. Privacy Module Structure

```
src/privacy/
├── mod.rs                   # Module exports and common functionality
├── profiles.rs              # Privacy profile management
├── levels.rs                # Protection level definitions and logic
├── fingerprint/             # Fingerprinting protection
│   ├── mod.rs               # Module exports
│   ├── canvas.rs            # Canvas fingerprinting protection
│   ├── webgl.rs             # WebGL fingerprinting protection
│   ├── audio.rs             # Audio fingerprinting protection
│   └── font.rs              # Font enumeration protection
├── storage/                 # Storage protection
│   ├── mod.rs               # Module exports
│   ├── cookies.rs           # Cookie management
│   ├── localstorage.rs      # LocalStorage/IndexedDB clearing
│   ├── cache.rs             # Cache management
│   └── evercookie.rs        # Evercookie mitigation
├── network/                 # Network protection
│   ├── mod.rs               # Module exports
│   ├── dns.rs               # DNS privacy enhancement
│   ├── referer.rs           # Referer header control
│   ├── useragent.rs         # User-agent management
│   └── tls.rs               # TLS fingerprinting mitigation
├── browsers/                # Browser-specific functionality
│   ├── mod.rs               # Module exports
│   ├── firefox.rs           # Firefox hardening
│   ├── chrome.rs            # Chrome hardening (future)
│   └── edge.rs              # Edge hardening (future)
└── isolation/               # Browser isolation
    ├── mod.rs               # Module exports
    └── firejail.rs          # Firejail integration
```

## 2. Protection Levels Implementation

We'll implement the protection levels (Basic, Standard, Strict, Custom) as a set of predefined configurations:

```rust
// In src/privacy/levels.rs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtectionLevel {
    Basic,
    Standard,
    Strict,
    Custom,
}

impl ProtectionLevel {
    // Get default settings for this protection level
    pub fn get_default_settings(&self) -> PrivacySettings {
        match self {
            Self::Basic => PrivacySettings {
                fingerprint: FingerprintSettings {
                    canvas_protection: false,
                    webgl_protection: false,
                    audio_protection: false,
                    font_protection: true,
                },
                storage: StorageSettings {
                    cookie_management: true,
                    localstorage_clearing: false,
                    cache_management: false,
                    evercookie_mitigation: false,
                },
                network: NetworkSettings {
                    dns_privacy: false,
                    referer_control: true,
                    user_agent_management: false,
                    tls_fingerprinting_mitigation: false,
                },
            },
            Self::Standard => PrivacySettings {
                fingerprint: FingerprintSettings {
                    canvas_protection: true,
                    webgl_protection: false,
                    audio_protection: true,
                    font_protection: true,
                },
                // More settings...
            },
            // Strict and Custom implementations...
        }
    }
}
```

## 3. Privacy Profiles

We'll store privacy profiles as JSON files in the `resources/profiles/` directory:

```rust
// In src/privacy/profiles.rs
pub struct PrivacyProfile {
    pub name: String,
    pub description: String,
    pub protection_level: ProtectionLevel,
    pub settings: PrivacySettings,
}

impl PrivacyProfile {
    // Load all predefined profiles
    pub fn load_predefined_profiles() -> Result<Vec<Self>, Error> {
        let profiles_dir = Path::new("resources/profiles");
        let mut profiles = Vec::new();
        
        for entry in fs::read_dir(profiles_dir)? {
            let path = entry?.path();
            if path.extension().unwrap_or_default() == "json" {
                let profile = Self::load_from_file(&path)?;
                profiles.push(profile);
            }
        }
        
        Ok(profiles)
    }
    
    // Load a single profile from a file
    pub fn load_from_file(path: &Path) -> Result<Self, Error> {
        let content = fs::read_to_string(path)?;
        let profile: Self = serde_json::from_str(&content)?;
        Ok(profile)
    }
    
    // Save a profile to a file
    pub fn save_to_file(&self, path: &Path) -> Result<(), Error> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
```

## 4. Firefox Hardening Implementation

Firefox hardening will modify the user's Firefox configuration:

```rust
// In src/privacy/browsers/firefox.rs
pub struct FirefoxHardener {
    profile_path: PathBuf,
}

impl FirefoxHardener {
    pub fn new(profile_path: PathBuf) -> Self {
        Self { profile_path }
    }
    
    // Apply hardening based on protection level
    pub fn apply_hardening(&self, level: ProtectionLevel) -> Result<Vec<String>, Error> {
        let prefs_file = self.profile_path.join("user.js");
        let settings = self.get_settings_for_level(level);
        
        let mut applied_settings = Vec::new();
        let mut content = String::new();
        
        for (key, value) in settings {
            content.push_str(&format!("user_pref(\"{}\", {});\n", key, value));
            applied_settings.push(key.clone());
        }
        
        fs::write(prefs_file, content)?;
        Ok(applied_settings)
    }
    
    // Get Firefox settings for the specified protection level
    fn get_settings_for_level(&self, level: ProtectionLevel) -> HashMap<String, String> {
        let mut settings = HashMap::new();
        
        // Common settings for all levels
        settings.insert("privacy.trackingprotection.enabled".to_string(), "true".to_string());
        
        match level {
            ProtectionLevel::Basic => {
                // Basic settings
                settings.insert("network.cookie.cookieBehavior".to_string(), "1".to_string());
                // More basic settings...
            },
            ProtectionLevel::Standard => {
                // Include all Basic settings
                let basic_settings = self.get_settings_for_level(ProtectionLevel::Basic);
                settings.extend(basic_settings);
                
                // Additional Standard settings
                settings.insert("privacy.resistFingerprinting".to_string(), "true".to_string());
                settings.insert("privacy.firstparty.isolate".to_string(), "true".to_string());
                // More standard settings...
            },
            ProtectionLevel::Strict => {
                // Include all Standard settings
                let standard_settings = self.get_settings_for_level(ProtectionLevel::Standard);
                settings.extend(standard_settings);
                
                // Additional Strict settings
                settings.insert("webgl.disabled".to_string(), "true".to_string());
                settings.insert("media.peerconnection.enabled".to_string(), "false".to_string());
                // More strict settings...
            },
            ProtectionLevel::Custom => {
                // Custom will be handled separately based on user preferences
            }
        }
        
        settings
    }
}
```

## 5. Firejail Integration

For browser isolation with Firejail:

```rust
// In src/privacy/isolation/firejail.rs
pub struct Firejail {
    firejail_path: PathBuf,
}

impl Firejail {
    pub fn new() -> Result<Self, Error> {
        // Find firejail executable
        let output = Command::new("which")
            .arg("firejail")
            .output()?;
        
        if !output.status.success() {
            return Err(Error::new(ErrorKind::NotFound, "Firejail not found"));
        }
        
        let path_str = String::from_utf8(output.stdout)?.trim().to_string();
        let firejail_path = PathBuf::from(path_str);
        
        Ok(Self { firejail_path })
    }
    
    // Launch a browser in a sandbox
    pub fn launch_browser(&self, browser: &str, profile: Option<&str>) -> Result<std::process::Child, Error> {
        let mut cmd = Command::new(&self.firejail_path);
        
        // Common firejail arguments
        cmd.arg("--private")
           .arg("--seccomp")
           .arg("--caps.drop=all")
           .arg("--nonewprivs");
           
        // Add browser-specific profile if available
        if let Some(profile_name) = profile {
            cmd.arg(format!("--profile={}", profile_name));
        } else {
            // Default to browser name
            cmd.arg(format!("--profile={}", browser));
        }
        
        // Add the browser command
        cmd.arg(browser);
        
        // Launch the browser
        let child = cmd.spawn()?;
        
        Ok(child)
    }
    
    // Check if firejail is available and working
    pub fn check_status(&self) -> Result<bool, Error> {
        let output = Command::new(&self.firejail_path)
            .arg("--version")
            .output()?;
        
        Ok(output.status.success())
    }
}
```

## 6. API Endpoints for Privacy Features

These will map to the appropriate handlers:

```rust
// In src/api/routes.rs
pub fn privacy_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/privacy")
            .wrap(TokenAuth)
            .route("/status", web::get().to(handlers::privacy::get_status))
            .route("/protection", web::get().to(handlers::privacy::get_protection_level))
            .route("/protection", web::put().to(handlers::privacy::set_protection_level))
            .route("/profiles", web::get().to(handlers::privacy::list_profiles))
            .route("/profiles/{name}", web::get().to(handlers::privacy::get_profile))
            .route("/profiles", web::post().to(handlers::privacy::create_profile))
            .route("/profiles/{name}", web::put().to(handlers::privacy::update_profile))
            .route("/profiles/{name}", web::delete().to(handlers::privacy::delete_profile))
            .service(
                web::scope("/harden")
                    .route("/firefox", web::post().to(handlers::privacy::harden_firefox))
                    .route("/firefox/status", web::get().to(handlers::privacy::check_firefox_status))
            )
            .route("/clean", web::post().to(handlers::privacy::clean_privacy_data))
            .service(
                web::scope("/fingerprint")
                    .route("", web::get().to(handlers::privacy::get_fingerprint_settings))
                    .route("", web::put().to(handlers::privacy::set_fingerprint_settings))
            )
            .service(
                web::scope("/storage")
                    .route("", web::get().to(handlers::privacy::get_storage_settings))
                    .route("", web::put().to(handlers::privacy::set_storage_settings))
            )
            .service(
                web::scope("/network")
                    .route("", web::get().to(handlers::privacy::get_network_settings))
                    .route("", web::put().to(handlers::privacy::set_network_settings))
                    .route("/dns", web::post().to(handlers::privacy::configure_dns))
            )
    );
}

