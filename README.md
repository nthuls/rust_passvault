# SecureVault: Password Manager & Privacy Shield

A security-focused, open-source solution that combines robust password management with advanced protection against tracking and malware.

![SecureVault Logo](resources/images/logo.png)

## 🌟 Overview

SecureVault is designed with simplicity in mind, offering powerful security features through a user-friendly interface. It protects your digital identity with military-grade encryption while defending against advanced tracking techniques and password-stealing malware.

![Dashboard Demo](resources/images/dashboard_demo.gif)

## ⚡ Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/securevault.git
cd securevault

# Run installer
./install.sh

# Launch application
securevault

# Access dashboard
# Open browser at http://localhost:5000
```

## 🔑 Key Features

### Core Features (Initial Release)
- **Secure Password Storage**: AES-256-GCM encryption with Argon2id key derivation
- **One-Click Protection**: Instantly secure your browsing environment
- **Database Flexibility**: Works with SQLite (default) or PostgreSQL (optional)
- **Browser Password Import**: Extract and secure passwords from Firefox (initial), Chrome/Edge (planned)
- **Simple, Intuitive UI**: Designed for users of all technical levels via web dashboard
- **Privacy Dashboard**: Visual security status with traffic light system
- **Firefox Hardening**: One-click privacy optimization for Firefox
- **Google Dork Builder**: Create advanced search queries for OSINT

### Upcoming Features
- **Auto-fill Integration**: Securely fill passwords in browsers
- **Advanced Anti-Tracking**: Protection against fingerprinting, supercookies, and more
- **Automatic Tool Installation**: One-click setup of privacy tools
- **Network-Level Protection**: DNS and traffic protection
- **Security Education**: Built-in resources to learn about threats
- **Cross-Browser Support**: Firefox, Chrome, Edge, and more

## 📊 Project Status

| Feature | Status |
|---------|--------|
| Password Vault Core | ✅ Operational |
| SQLite Support | ⏳ In Progress |
| Firefox Import | ✅ Operational |
| Flask Web UI | 🔜 Planned |
| Browser Extension | 🔜 Planned |
| Privacy Dashboard | 🔜 Planned |
| Google Dork Builder | 🔜 Planned |

## 🛠️ Installation

### Prerequisites
- Linux (Ubuntu 20.04+ or similar distribution)
- Python 3.8+
- Rust 1.60+
- SQLite (included) or PostgreSQL (optional)

### Quick Install
```bash
# Clone repository
git clone https://github.com/yourusername/securevault.git
cd securevault

# Run installer
./install.sh
```

## 🚀 Usage

1. **Launch SecureVault**
   ```bash
   securevault
   ```

2. **Create Master Password**
   - Choose a strong master password
   - Configure optional recovery options (email + security questions)

3. **Import Existing Passwords** (Optional)
   - Import from Firefox (other browsers coming soon)
   - Import from CSV files

4. **Activate Protection**
   - Click "Protect My Browser" for instant security
   - Choose protection level: Basic, Standard, or Strict

### CLI Commands

SecureVault provides a comprehensive command-line interface:

```bash
# Basic usage
securevault                      # Launch the web dashboard
securevault --help               # Show help message

# Password management
securevault --list               # List all sites in vault
securevault --import firefox     # Import Firefox passwords
securevault --import csv file.csv # Import from CSV
securevault --export backup.csv  # Export to CSV (encrypted)

# Privacy features
securevault --privacy-check      # Check browser privacy status
securevault --harden firefox     # Apply hardening to Firefox
securevault --clean              # Run privacy cleanup

# Advanced usage
securevault --no-gui             # Run in headless mode
securevault --db sqlite:data.db  # Specify database location
```

## 🔌 Browser Extension

![Extension Demo](resources/images/extension_demo.png)

The browser extension is an **optional but recommended** component that enhances SecureVault's functionality:

- **Auto-fill**: Securely fill credentials without clipboard exposure
- **Active Protection**: Real-time fingerprinting defense
- **Site Security**: Visual indicator of site password health
- **Vault Access**: Quick access to your password vault

The extension communicates with the main application via a secure native messaging channel, ensuring that sensitive operations remain in the protected core application.

### Extension Installation

The extension can be installed directly from the SecureVault dashboard or manually from browser stores:
- Firefox: [Mozilla Add-ons](https://addons.mozilla.org/)
- Chrome/Edge: [Chrome Web Store](https://chrome.google.com/webstore/)

## 🏗️ Architecture

SecureVault follows a MobSF-inspired architecture:

```
+----------------------------+
|   SecureVault Binary CLI   |  <-- Entry point (runs Flask)
+----------------------------+
            |
            v
+----------------------------+
|  Flask Web Dashboard (UI)  |
+----------------------------+
            |
            v
+----------------------------+
|  Rust Vault Core (via IPC) |
+----------------------------+
            |
            +--> SQLite/PostgreSQL
```

- **Rust Core**: Handles all cryptographic operations and vault management
- **Flask Server**: Provides the web UI accessible at `localhost:5000`
- **Browser Extension**: Communicates with local server for auto-fill and protection

## 🔐 Security Philosophy

SecureVault prioritizes security over convenience:

- **Zero Knowledge**: Your master password is never stored or transmitted
- **Local First**: All data stays on your device by default
- **Responsibility**: We provide tools, not hand-holding - your security is ultimately in your hands
- **Limited Recovery**: Master password recovery requires both email token and security questions

## 🔧 Technical Details

### Project Structure

```
rustvault/
├── .env                          # Environment variables
├── .gitignore
├── backups/                      # Backup storage
├── src/                          # Rust core code (existing)
│   ├── config.rs
│   ├── crypto.rs
│   ├── db/                       # Enhanced database module
│   │   ├── mod.rs                # Database abstraction
│   │   ├── postgres.rs           # PostgreSQL implementation (existing)
│   │   └── sqlite.rs             # SQLite implementation (new)
│   ├── firefox/                  # Firefox integration (existing)
│   │   ├── credentials.rs
│   │   ├── mod.rs
│   │   ├── nss.rs
│   │   └── profile.rs
│   ├── generators/               # Password generation (existing)
│   │   ├── mod.rs
│   │   └── password.rs
│   ├── importers/                # Password importers (existing)
│   │   ├── csv.rs
│   │   ├── firefox.rs
│   │   └── mod.rs
│   ├── privacy/                  # New privacy module
│   │   ├── mod.rs
│   │   ├── browser_config.rs     # Browser hardening configs
│   │   ├── fingerprint.rs        # Anti-fingerprinting
│   │   └── cleanup.rs            # Privacy cleanup routines
│   ├── main.rs                   # Application entry point
│   ├── models.rs                 # Data structures
│   └── utils.rs                  # Utility functions
│
├── python/                       # Python Flask UI layer
│   ├── __init__.py
│   ├── __main__.py               # Python entry point
│   ├── web/                      # Web interface
│   │   ├── __init__.py
│   │   ├── app.py                # Flask application
│   │   ├── views/                # Route handlers
│   │   ├── static/               # CSS, JS, images
│   │   └── templates/            # Jinja2 templates
│   ├── bridge/                   # Rust-Python bridge
│   │   ├── __init__.py
│   │   └── vault.py              # Interface to Rust vault
│   └── utils/                    # Python utilities
│       ├── __init__.py
│       └── system.py             # System interaction
│
├── extension/                    # Browser extension (planned)
│   ├── manifest.json
│   ├── background.js
│   ├── popup/
│   │   ├── popup.html
│   │   └── popup.js
│   └── content/
│       └── autofill.js
│
├── scripts/                      # Helper scripts
│   ├── build.sh                  # Build script
│   ├── install_tools.sh          # Privacy tools installer
│   └── setup_db.sh               # Database setup
│
├── migrations/                   # Database migrations
│   ├── postgres/                 # PostgreSQL migrations
│   │   └── initial.sql
│   └── sqlite/                   # SQLite migrations
│       └── initial.sql
│
├── resources/                    # Application resources
│   ├── images/                   # Screenshots and icons
│   ├── profiles/                 # Privacy protection profiles
│   └── education/                # User education materials
│
├── docs/                         # Documentation
│   ├── SECURITY.md               # Threat model and security guarantees
│   ├── PRIVACY.md                # Privacy practices and data handling
│   ├── RECOVERY.md               # Master password recovery process
│   ├── ABOUT_FIREFOX.md          # Firefox hardening guide
│   ├── CONTRIBUTING.md           # Developer guidelines
│   ├── VAULT_FORMAT.md           # Vault structure specification
│   └── config_flags.md           # CLI options and environment variables
│
├── Cargo.toml                    # Rust dependencies
├── pyproject.toml                # Python dependencies
└── README.md                     # Project documentation
```

### Component Architecture

```
+-----------------------+      +---------------------+
|                       |      |                     |
|   Flask Web UI        |<---->|   Rust Core Vault   |
|   (MobSF-style)       |      |   (FIPS Verified)   |
|                       |      |                     |
+-----------------------+      +---------------------+
          ^                             ^
          |                             |
          v                             v
+-----------------------+      +---------------------+
|                       |      |                     |
|   Privacy Shield      |<---->|   Database Layer    |
|  (Browser & System)   |      | (SQLite/PostgreSQL) |
|                       |      |                     |
+-----------------------+      +---------------------+
          ^                             ^
          |                             |
          v                             v
+-----------------------+      +---------------------+
|                       |      |                     |
|  Browser Extensions   |<---->|   System Services   |
|  (Auto-fill/Privacy)  |      |  (Tools & Cleanup)  |
|                       |      |                     |
+-----------------------+      +---------------------+
```

### Database Strategy

SecureVault implements a dual-database strategy:

1. **SQLite** (Default)
   - Used by default - no additional setup required
   - Self-contained database file
   - Perfect for most users

2. **PostgreSQL** (Optional)
   - Can be configured for advanced users
   - Better performance for large password collections
   - Support for concurrent access

The application seamlessly chooses the appropriate database system during initialization.

### Security Measures

- **Encryption**: AES-256-GCM for data at rest
- **Key Derivation**: Argon2id with high cost parameters
- **Brute Force Protection**: Progressive delays after failed attempts
- **Memory Protection**: Sensitive data is wiped from memory when not in use
- **Secure Delete**: Overwrite deleted entries with random data
- **CSRF Protection**: Prevents cross-site request forgery in web interface
- **Audit Logging**: Records security-critical events for review

## 📝 Development Plan

### Phase 1: Core Functionality (Current)
- Password vault core implementation
- Database flexibility (SQLite/PostgreSQL)
- Basic Flask web UI implementation
- Firefox password import

### Phase 2: Enhanced Protection
- Browser integration for auto-fill
- Basic anti-tracking implementation
- Privacy dashboard development
- Tool installation automation

### Phase 3: Advanced Features
- Full anti-tracking suite
- Network-level protection
- Chrome/Edge browser import
- Security education resources
- Google Dork Builder

### Phase 4: Polish & Expansion
- Cross-platform support (Windows, macOS)
- Sync capabilities (optional)
- Advanced customization options
- Performance optimizations

## 💪 Privacy Protections

### Protection Levels Visualization

![Protection Levels](resources/images/protection_levels.png)

| Level | Description | Impact on Sites | Features Enabled |
|-------|-------------|-----------------|-----------------|
| Basic | Essential protections with minimal site breakage | Very Low | Cookie Management, Basic Fingerprint Defense |
| Standard | Balanced protection for everyday browsing | Low-Medium | All Basic + Canvas Protection, Storage Isolation |
| Strict | Maximum privacy at the cost of some functionality | Medium-High | All Standard + WebGL Protection, Network Shields |
| Custom | User-defined protection configuration | Varies | User-selected combination of protections |

### Fingerprinting Protection
- Canvas/WebGL fingerprinting
- Audio fingerprinting
- Font enumeration
- Hardware fingerprinting

### Storage Protection
- Cookie management
- LocalStorage/IndexedDB clearing
- Cache management
- Evercookie mitigation

### Network Protection
- DNS privacy enhancement
- Referer header control
- User-agent management
- TLS fingerprinting mitigation

## 🧰 Privacy Tools Integration

SecureVault integrates with established privacy tools:

- **uBlock Origin**: Ad and tracker blocking
- **Privacy Badger**: Learning-based protection
- **Containers**: Site isolation
- **HTTPS Everywhere**: Secure connection enforcement
- **OneTab**: Reduce browser fingerprinting surface

## 🔄 Backup & Recovery

SecureVault takes data protection seriously and provides robust backup options:

### Automatic Backups
- Scheduled encrypted backups of your vault
- Configurable backup frequency and retention
- Backup verification to ensure integrity

### Manual Export Options
- Encrypted vault export (.vault format)
- CSV export with encryption option
- Individual password export

### Master Password Recovery

**Important**: We follow a split-knowledge approach for master password recovery:

1. Recovery requires both an email token AND correct answers to security questions
2. Recovery attempts are rate-limited and time-restricted
3. Recovery process is fully audited
4. Users can disable recovery entirely for maximum security

We recommend:
1. Using a separate password manager to store your master password
2. Creating a secure offline backup of your master password
3. Setting up the optional recovery mechanism during initial setup

## 🔍 Anti-Malware Approach

SecureVault protects against password-stealing malware through:

1. **Secure Storage**: Passwords are never stored in plain text
2. **Memory Protection**: Sensitive data is cleared from memory when not in use
3. **Browser Isolation**: Optional sandboxing of browser processes
4. **Clipboard Protection**: Automatic clipboard clearing
5. **Phishing Detection**: Warning for suspicious password entry forms

## 🛡️ Privacy Profiles

The `resources/profiles/` directory contains predefined privacy profiles that control:

- Browser hardening settings
- Fingerprinting protection levels
- Cookie and storage policies
- Network privacy configurations

These profiles provide templates for different privacy needs:

- **standard.json**: Balanced protection for everyday use
- **strict.json**: Maximum protection for privacy-sensitive browsing
- **workspace.json**: Optimized for work environments
- **banking.json**: Enhanced protection for financial sites

Users can create custom profiles via the UI or by editing profile JSON files.

## 🧠 Educational Integration

SecureVault includes built-in educational content for users:

- **Vault Tab**: "What is AES encryption?"
- **Firefox Tab**: "What is fingerprinting?"
- **Dork Builder**: "What is a Google Dork?"
- **Privacy Tab**: "Why OneTab helps privacy?"
- **Recovery**: "Why we don't store your password"

These tooltips and popups help users understand security concepts without overwhelming them.

## 🧪 Development

### Prerequisites

- Python 3.8+
- Rust 1.60+
- SQLite (included) or PostgreSQL

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/yourusername/securevault.git
cd securevault

# Install dependencies
pip install -r requirements.txt
cargo build

# Run in development mode
./dev/run.sh
```

### Testing

```bash
# Run all tests
pytest tests/
cargo test

# Run specific test categories
pytest tests/test_flask_api.py
cargo test vault_encryption
```

## 🤝 Contribution

Contributions are welcome! We're looking for help with:

- UI/UX improvements
- Additional browser support
- Enhanced privacy protections
- Educational content development
- Testing and bug reports

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## 📋 Requirements & Dependencies

### Rust Dependencies
- tokio
- sqlx (with PostgreSQL and SQLite features)
- argon2
- aes-gcm
- clap
- serde

### Python Dependencies
- Flask
- requests
- cryptography
- pysqlite3 (for SQLite)
- psycopg2 (for PostgreSQL)
- pillow
- pyxdg

### Optional Dependencies
- Firejail (for browser sandboxing)
- dnscrypt-proxy (for DNS protection)

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 🔐 Security

We take security seriously. If you discover a security vulnerability, please send an email to security@securevault.example.com rather than opening a public issue.

**Disclosure Policy**: We aim to respond to security reports within 48 hours and provide a timeline for resolution within 7 days. Critical vulnerabilities receive highest priority and are typically addressed within 72 hours.

We follow responsible disclosure practices and may offer credit/acknowledgment for significant security findings.

## 🙏 Acknowledgments

- The Rust and Python communities
- Privacy advocates and security researchers
- All contributors and testers

## 📞 Contact

- GitHub Issues: Please report bugs through the issue tracker
- Email: contact@securevault.example.com

---

*SecureVault: Security without compromise.*


# TO DO 
You're absolutely right. Breaking down this monolithic main.rs file into multiple modules would significantly improve maintainability and readability. Here's how I'd recommend restructuring it in the future:

## Recommended Module Structure

```
src/
├── main.rs                   # Entry point, minimal code
├── cli/                      # CLI-related modules
│   ├── mod.rs                # CLI module exports
│   ├── menu.rs               # Interactive menu handling
│   ├── commands.rs           # Command definitions (CliCommand enum)
│   └── handlers.rs           # Command execution handlers
├── api/                      # API-related modules
│   ├── mod.rs                # API module exports
│   ├── types.rs              # Request/response data structures
│   ├── routes.rs             # API endpoint routing
│   └── handlers.rs           # API request handlers
├── web/                      # Web interface integration
│   ├── mod.rs                # Web module exports
│   └── server.rs             # Flask server management
├── core/                     # Core functionality
│   ├── mod.rs                # Core module exports
│   ├── vault.rs              # Password vault operations
│   ├── auth.rs               # Authentication logic
│   └── config.rs             # Application configuration
├── utils/                    # Utility functions
│   ├── mod.rs                # Utils module exports
│   ├── io.rs                 # I/O helpers
│   └── format.rs             # Formatting helpers
└── (existing modules)        # Existing modules like crypto, db, etc.
```

## Specific Improvements

1. **CLI Module**:
   - Move the interactive menu code into its own module
   - Create separate handlers for each command
   - Define clear interfaces between UI and business logic

2. **API Module**:
   - Separate request/response types from handling logic
   - Implement proper routing for API requests
   - Create standard error handling

3. **Core Module**:
   - Move vault operations into a dedicated Vault struct
   - Implement proper state management
   - Create clear interfaces for different operations

4. **General Improvements**:
   - Implement proper error type hierarchy
   - Use builder patterns for complex objects
   - Add comprehensive documentation

## Implementation Approach

1. **Incremental Refactoring**:
   - Start by extracting the JSON API handlers
   - Then move the CLI menu logic
   - Finally, extract shared business logic

2. **Test Coverage**:
   - Add tests as you extract modules
   - Ensure each module can be tested in isolation

3. **Documentation**:
   - Add module-level documentation
   - Document public interfaces
   - Add examples where appropriate

This modular structure will make the codebase much easier to maintain and extend in the future. It will also make it easier for other developers to understand and contribute to the project.

# THESE LINES ARE MEANT TO CLEAR THE SCREEN WITH CODE 
    // print!("\x1B[3J\x1B[2J\x1B[H");
    // print!("\x1B[2J\x1B[1;1H");
    // print!("\x1B[2J\x1B[1;1H");


# opensearch password
sudo env OPENSEARCH_INITIAL_ADMIN_PASSWORD=Nthuls_victor_2001 apt-get install opensearch

# rabbitmq password
rabbitmqctl add_user opencti opencti_nthuls_opencti

# minio_passwords
Environment="MINIO_ROOT_USER=minio"
Environment="MINIO_ROOT_PASSWORD=minio_nthulis_password"

{
  "app": {
    "port": 4000,
    "base_path": "",
    "base_url": "http://0.0.0.0:4000/",
    "enterprise_edition_license": "",
    "public_dashboard_authorized_domains": "",
    "notifier_authorized_functions": [
      "if",
      "for",
      "forEach",
      "while",
      "stringify",
      "Date",
      "toLocaleString",
      "isArray",
      "keys",
      "function"
    ],
    "enabled": true,
    "enabled_ui": true,
    "enabled_dev_features": [],
    "https_cert": {
      "ca": [],
      "key": null,
      "crt": null,
      "reject_unauthorized": true,
      "cookie_secure": false
    },
    "app_logs": {
      "logs_level": "info",
      "logs_files": true,
      "logs_console": true,
      "logs_max_files": 7,
      "logs_directory": "./logs",
      "logs_redacted_inputs": [
        "password",
        "secret",
        "token",
        "api_token",
        "authentication_value",
        "enterprise_license"
      ],
      "extended_error_message": false
    },
    "filename_to_mimes": {
      "pdf_report": "application/pdf",
      ".yar": "text/yara+plain"
    },
    "audit_logs": {
      "logs_files": true,
      "logs_console": true,
      "logs_max_files": 7,
      "logs_directory": "./logs"
    },
    "event_loop_logs": {
      "enabled": false,
      "max_time": 1000
    },
    "graphql": {
      "armor_protection": {
        "disabled": true,
        "max_depth": 20,
        "max_directives": 20,
        "max_tokens": 100000,
        "cost_limit": 3000000,
        "block_field_suggestion": true
      },
      "batching_protection": {
        "mutation_default": 1,
        "query_default": 2,
        "query_subtypes": 4
      },
      "playground": {
        "enabled": true,
        "force_disabled_introspection": true
      }
    },
    "telemetry": {
      "pyroscope": {
        "enabled": false,
        "identifier": "OpenCTI",
        "exporter": ""
      },
      "tracing": {
        "enabled": false,
        "exporter_otlp": "",
        "exporter_zipkin": ""
      },
      "metrics": {
        "enabled": false,
        "exporter_otlp": "",
        "exporter_prometheus": 14269
      }
    },
    "health_access_key": "9d44b735-9959-4e68-9414-3978d026b7e4-health-access-key",
    "request_timeout": 1200000,
    "session_timeout": 1200000,
    "session_cookie": false,
    "child_locking_process": {
      "enabled": true
    },
    "locked_account_statuses": {
      "Inactive": "Your account has been marked inactive. If you would like to reactivate your account, please contact your administrator.",
      "Locked": "Your account has been locked for security reasons. Please contact your administrator."
    },
    "account_statuses_default": "Active",
    "session_idle_timeout": 0,
    "session_manager": "shared",
    "rate_protection": {
      "time_window": 1,
      "max_requests": 10000
    },
    "concurrency": {
      "retry_count": 100,
      "retry_delay": 250,
      "retry_jitter": 100,
      "max_ttl": 60000,
      "extension_threshold": 5000
    },
    "live_stream": {
      "cache_max_size": 5000,
      "cache_max_time": 2
    },
    "exclusion_list": {
      "file_max_size": 10000000
    },
    "performance_logger": false,
    "map_tile_server_dark": "https://map.opencti.io/styles/filigran-dark2/{z}/{x}/{y}.png",
    "map_tile_server_light": "https://map.opencti.io/styles/filigran-light2/{z}/{x}/{y}.png",
    "reference_attachment": false,
    "python_execution": "native",
    "python_execution_venv": "../../../.python-venv/lib/python3.12/site-packages",
    "artifact_zip_password": "infected",
    "admin": {
      "email": "victornthuli269@gmail.com",
      "password": "bdd453da-05d3-4f54-ab91-2a6508e4c319-Nthuls-2025",
      "token": "9d44b735-9959-4e68-9414-3978d026b7e4-token-nthuls",
      "externally_managed": false
    },
    "group_confidence_level": {
      "max_confidence_default": 100
    },
    "trash": {
      "enabled": true
    },
    "csv_ingestion": {
      "max_bundle_size": 1000
    },
    "validation_mode": "workbench",
    "dissemination_list": {
      "to_email": "no-reply@filigran.io",
      "max_list_size": 500
    }
  },
  "demo_mode": false,
  "http_proxy": "",
  "https_proxy": "",
  "no_proxy": "",
  "https_proxy_ca": [],
  "https_proxy_reject_unauthorized": false,
  "relations_deduplication": {
    "past_days": 30,
    "next_days": 30,
    "created_by_based": false
  },
  "protected_sensitive_config": {
    "enabled": true,
    "markings": {
      "enabled": true,
      "protected_definitions": [
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
        "TLP:RED",
        "PAP:CLEAR",
        "PAP:GREEN",
        "PAP:AMBER",
        "PAP:RED"
      ]
    },
    "groups": {
      "enabled": true,
      "protected_names": ["Administrators", "Connectors", "Default"]
    },
    "roles": {
      "enabled": true,
      "protected_names": ["Administrator", "Connector", "Default"]
    },
    "rules": {
      "enabled": true
    },
    "ce_ee_toggle": {
      "enabled": true
    },
    "connector_reset": {
      "enabled": true
    },
    "file_indexing": {
      "enabled": true
    },
    "platform_organization": {
      "enabled": true
    }
  },
  "ai": {
    "enabled": true,
    "type": "mistralai",
    "endpoint": "",
    "token": "",
    "model": "",
    "version": "",
    "model_images": "",
    "max_tokens": 30000,
    "insights_refresh_timeout": 60,
    "ai_azure_instance": "",
    "ai_azure_deployment": ""
  },
  "xtm": {
    "openbas_url": "",
    "openbas_token": "",
    "openbas_reject_unauthorized": false,
    "openbas_disable_display": false,
    "openerm_url": "",
    "openrm_token": "",
    "openmtd_url": "",
    "openmtd_token": "",
    "xtmhub_url": "https://hub.filigran.io"
  },
  "data_sharing": {
    "max_csv_feed_result": 5000
  },
  "rule_engine": {
    "enabled": true,
    "lock_key": "rule_engine_lock"
  },
  "history_manager": {
    "enabled": true,
    "include_inferences": true,
    "lock_key": "history_manager_lock"
  },
  "activity_manager": {
    "enabled": true,
    "lock_key": "activity_manager_lock"
  },
  "connector_manager": {
    "enabled": true,
    "lock_key": "connector_manager_lock",
    "works_day_range": 7,
    "batch_size": 10000,
    "interval": 60000
  },
  "import_csv_built_in_connector": {
    "enabled": true,
    "interval": 10000,
    "validate_before_import": false,
    "bulk_creation_size": 5000
  },
  "task_scheduler": {
    "enabled": true,
    "lock_key": "task_manager_lock",
    "interval": 10000
  },
  "expiration_scheduler": {
    "enabled": true,
    "lock_key": "expired_manager_lock",
    "interval": 300000
  },
  "notification_manager": {
    "enabled": true,
    "lock_live_key": "notification_live_manager_lock",
    "lock_digest_key": "notification_digest_manager_lock",
    "interval": 10000
  },
  "telemetry_manager": {
    "lock_key": "telemetry_manager_lock"
  },
  "playbook_manager": {
    "enabled": true,
    "lock_key": "playbook_manager_lock",
    "lock_cron_key": "playbook_cron_manager_lock",
    "interval": 60000,
    "cron_max_size": 500
  },
  "indicator_decay_manager": {
    "enabled": true,
    "lock_key": "indicator_decay_manager_lock",
    "batch_size": 10000,
    "interval": 60000
  },
  "garbage_collection_manager": {
    "enabled": true,
    "lock_key": "garbage_collection_manager_lock",
    "batch_size": 10000,
    "interval": 60000,
    "deleted_retention_days": 7
  },
  "publisher_manager": {
    "enabled": true,
    "lock_key": "publisher_manager_lock",
    "interval": 10000
  },
  "sync_manager": {
    "enabled": true,
    "lock_key": "sync_manager_lock",
    "interval": 10000
  },
  "ingestion_manager": {
    "enabled": true,
    "lock_key": "ingestion_manager_lock",
    "interval": 30000,
    "taxii_feed": {
      "limit_per_request": 0
    },
    "rss_feed": {
      "min_interval_minutes": 5,
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    },
    "csv_feed": {
      "min_interval_minutes": 5
    }
  },
  "retention_manager": {
    "enabled": true,
    "lock_key": "retention_manager_lock",
    "interval": 30000
  },
  "file_index_manager": {
    "enabled": true,
    "lock_key": "file_index_manager_lock",
    "stream_lock_key": "file_index_manager_stream_lock",
    "interval": 60000
  },
  "exclusion_list_cache_build_manager": {
    "enabled": true,
    "lock_key": "exclusion_list_cache_build_manager_lock",
    "interval": 10000
  },
  "exclusion_list_cache_sync_manager": {
    "lock_key": "exclusion_list_cache_sync_manager_lock",
    "interval": 10000
  },
  "redis": {
    "mode": "single",
    "namespace": "",
    "hostname": "localhost",
    "use_ssl": false,
    "ca": [],
    "port": 6379,
    "host_ip_family": 4,
    "trimming": 2000000
  },
  "elasticsearch": {
    "index_prefix": "opencti",
    "url": "https://100.121.152.33:9200",
    "username":"admin",
    "password":"Nthuls_victor_2001",
    "ssl_reject_unauthorized": false,
    "ssl_ca": ["/etc/opensearch/root-ca.pem"], 
    "engine_selector": "auto",
    "engine_check": true,
    "index_creation_pattern": "-000001",
    "search_wildcard_prefix": false,
    "search_fuzzy": false,
    "max_pagination_result": 5000,
    "default_pagination_result": 500,
    "max_bulk_operations": 5000,
    "max_runtime_resolutions": 5000,
    "max_concurrency": 4
  },
  "minio": {
    "bucket_name": "opencti-bucket",
    "bucket_region": "us-east-1",
    "endpoint": "100.121.152.33",
    "port": 9000,
    "use_ssl": false,
    "access_key": "minio",
    "secret_key": "minio_nthulis_password",
    "use_aws_role": false,
    "excluded_files": [".DS_Store"],
    "disable_checksum_validation": false
  },
  "rabbitmq": {
    "queue_prefix": "",
    "hostname": "localhost",
    "vhost": "/",
    "use_ssl": false,
    "use_ssl_ca": [],
    "port": 5672,
    "port_management": 15672,
    "management_ssl": false,
    "username": "opencti",
    "password": "opencti_nthuls_opencti",
    "queue_type": "classic"
  },
  "smtp": {
    "hostname": "smtp.gmail.com",
    "use_ssl": false,
    "reject_unauthorized": false,
    "port": 587,
    "username": "ngashauth@gmail.com",
    "password": "ijdmzeuvuehbtxje"
  },
  "providers": {
    "local": {
      "strategy": "LocalStrategy"
    }
  }
}


# OPENCTI SERVICE 

Perfect — since you've updated OpenSearch to `127.0.0.1` and fixed the token in `production.json`, OpenCTI is ready to be daemonized properly.

---

### ✅ Let’s make **OpenCTI a systemd service**

#### 1. **Create a systemd service file**

```bash
sudo nano /etc/systemd/system/opencti.service
```

#### 2. **Paste the following config** (adjust paths and user as needed):

```ini
[Unit]
Description=OpenCTI GraphQL Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/opencti-6.6.17/opencti-platform/opencti-graphql
ExecStart=/root/opencti-6.6.17/opencti-platform/opencti-graphql/node_modules/.bin/yarn serv
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

---

### ✅ 3. **Reload and enable the service**

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable opencti
sudo systemctl start opencti
```

---

### ✅ 4. **Check status and logs**

```bash
sudo systemctl status opencti
journalctl -u opencti -f
```

---

### 💡 Optional improvements

If you're using a virtualenv for Python or need to run multiple components (worker, connector, etc.), you may want to define separate service files for them or use a [Process Manager like `pm2`](https://pm2.keymetrics.io/) for advanced setups.

Let me know if you want services for the **workers**, **connectors**, or **frontend UI** as well.
