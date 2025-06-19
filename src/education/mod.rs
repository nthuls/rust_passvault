// src/education/mod.rs
use std::collections::HashMap;
use std::error::Error;
use uuid::Uuid;

pub struct EducationManager {
    topics: HashMap<String, TopicContent>,
}

pub struct TopicContent {
    pub id: String,
    pub title: String,
    pub content: String,
    pub category: String,
    pub difficulty: String,
    pub related_topics: Vec<String>,
}

impl EducationManager {
    pub fn new() -> Self {
        let mut topics = HashMap::new();
        
        // Initialize with some predefined topics
        topics.insert("passwords".to_string(), TopicContent {
            id: "passwords".to_string(),
            title: "Password Security Fundamentals".to_string(),
            content: r#"# Password Security Fundamentals

Strong passwords are the first line of defense against unauthorized access to your accounts. Here are key principles:

## 1. Length is Strength
- Use at least 12 characters, preferably more
- Each additional character exponentially increases security

## 2. Complexity Matters
- Mix uppercase and lowercase letters
- Include numbers and special characters
- Avoid common patterns like keyboard rows (qwerty)

## 3. Avoid Common Mistakes
- Don't use personal information (names, birthdays)
- Don't use dictionary words without modification
- Don't reuse passwords across multiple sites

## 4. Modern Recommendations
- Use a passphrase (multiple random words) for better security and memorability
- Example: "correct-horse-battery-staple" is stronger than "P@ssw0rd!"
- Consider using a password manager like RustVault

## 5. Regular Updates
- Change passwords periodically (every 3-6 months)
- Change immediately if a service reports a data breach

Remember: The most secure password is one you don't know yourself—use a password manager!
"#.to_string(),
            category: "Security Basics".to_string(),
            difficulty: "beginner".to_string(),
            related_topics: vec!["2fa".to_string(), "encryption".to_string()],
        });
        
        topics.insert("2fa".to_string(), TopicContent {
            id: "2fa".to_string(),
            title: "Two-Factor Authentication".to_string(),
            content: r#"# Two-Factor Authentication (2FA)

Two-factor authentication adds an extra layer of security beyond just a password.

## What is 2FA?
Two-factor authentication requires two different types of proof:
1. Something you know (password)
2. Something you have (phone, security key)
3. Something you are (fingerprint, face)

## Common 2FA Methods
- **SMS Codes**: Text messages with verification codes
- **Authentication Apps**: Generate time-based codes (Google Authenticator, Authy)
- **Security Keys**: Physical devices like YubiKey
- **Biometrics**: Fingerprints, facial recognition

## Security Comparison
From least to most secure:
1. SMS (vulnerable to SIM swapping)
2. Email-based verification
3. Authentication apps
4. Hardware security keys

## Setting Up 2FA
Most services offer 2FA in account security settings:
1. Enable 2FA in settings
2. Choose verification method
3. Set up backup methods/recovery codes
4. Store recovery codes securely

## Best Practices
- Use authenticator apps over SMS when possible
- Keep backup codes in a secure location
- Set up multiple recovery methods
- Never share verification codes with anyone

2FA is like having a second lock on your door—even if attackers get your password, they still can't get in without the second factor.
"#.to_string(),
            category: "Security Basics".to_string(),
            difficulty: "beginner".to_string(),
            related_topics: vec!["passwords".to_string(), "security_keys".to_string()],
        });
        
        topics.insert("encryption".to_string(), TopicContent {
            id: "encryption".to_string(),
            title: "Understanding Encryption".to_string(),
            content: r#"# Understanding Encryption

Encryption is the process of encoding information so that only authorized parties can access it.

## Basic Concepts
- **Plaintext**: Original, readable data
- **Ciphertext**: Encrypted, scrambled data
- **Key**: Secret information used to encrypt/decrypt data
- **Algorithm**: The mathematical process for encryption

## Types of Encryption

### Symmetric Encryption
- Uses the same key for encryption and decryption
- Examples: AES-256, ChaCha20
- Fast but requires secure key sharing
- Used for: File encryption, disk encryption

### Asymmetric Encryption
- Uses a key pair: public key and private key
- Public key encrypts, private key decrypts
- Examples: RSA, ECC
- Slower but more secure for communication
- Used for: HTTPS, secure messaging, digital signatures

## Encryption in Practice

### End-to-End Encryption (E2EE)
- Only the communicating users can read messages
- Not even the service provider can access content
- Used in: Signal, WhatsApp, ProtonMail

### Transport Layer Security (TLS)
- Secures data in transit across the internet
- Provides: authentication, confidentiality, integrity
- Used in: HTTPS websites (look for the padlock icon)

## How RustVault Uses Encryption
RustVault protects your passwords using AES-256-GCM encryption with Argon2id key derivation. This means:
- Your master password is never stored directly
- Even if the database is compromised, passwords remain secure
- Each password is individually encrypted for maximum security

Remember: Encryption is only as strong as the key protecting it. A strong master password is essential!
"#.to_string(),
            category: "Technical Concepts".to_string(),
            difficulty: "intermediate".to_string(),
            related_topics: vec!["passwords".to_string(), "aes".to_string()],
        });
        
        topics.insert("fingerprinting".to_string(), TopicContent {
            id: "fingerprinting".to_string(),
            title: "Browser Fingerprinting".to_string(),
            content: r#"# Browser Fingerprinting

Browser fingerprinting is a technique used to identify and track users based on their browser and device characteristics.

## What Is Collected?
- **Hardware Information**: GPU, CPU, screen resolution
- **Browser Settings**: Installed plugins, fonts, time zone
- **Behavior**: Mouse movements, scrolling patterns
- **APIs**: Canvas rendering, WebGL, audio processing

## Common Fingerprinting Techniques

### Canvas Fingerprinting
- Forces browser to render invisible text/graphics
- Subtle differences in rendering create a unique identifier
- Nearly impossible to detect by users

### Font Fingerprinting
- Checks which fonts are installed on your system
- Creates a profile based on font availability and rendering

### WebGL Fingerprinting
- Uses 3D graphics capabilities to identify GPU and drivers
- Extremely precise and difficult to spoof

### Audio Fingerprinting
- Analyzes how your device processes audio
- Creates unique signature based on audio stack

## How Fingerprinting Differs from Cookies
- **Persistence**: Remains even after clearing cookies
- **Invisibility**: No notifications or permissions required
- **Pervasiveness**: Works across different browsers/sessions

## Protection Methods
RustVault offers several protections:
- Canvas randomization (adds subtle noise to canvas operations)
- WebGL blocking or spoofing
- Font enumeration protection
- User-agent normalization

## Detecting Fingerprinting
Visit sites like:
- AmIUnique.org
- Panopticlick (EFF)
- Browserleaks.com

These show how unique your browser appears and what data can be collected.

Remember: Complete fingerprinting protection often requires trade-offs in website functionality and performance.
"#.to_string(),
            category: "Privacy Threats".to_string(),
            difficulty: "intermediate".to_string(),
            related_topics: vec!["tracking".to_string(), "browser_hardening".to_string()],
        });
        
        topics.insert("dorks".to_string(), TopicContent {
            id: "dorks".to_string(),
            title: "Understanding Google Dorks".to_string(),
            content: r#"# Understanding Google Dorks

Google Dorks are specialized search queries that use advanced operators to find specific information that might not be easily accessible through regular searches.

## What Are Google Dorks?
Google Dorks use Google's advanced search operators to find specific types of content, often revealing sensitive information that was unintentionally exposed on the internet.

## Common Operators

### `site:`
- Restricts search to a specific website
- Example: `site:example.com password`

### `filetype:`
- Searches for specific file types
- Example: `filetype:pdf confidential`

### `intext:`
- Finds pages containing specific text
- Example: `intext:"internal use only"`

### `intitle:`
- Searches for pages with specific words in the title
- Example: `intitle:"index of" passwords`

### `inurl:`
- Finds pages with specific words in the URL
- Example: `inurl:admin`

### `-` (minus)
- Excludes results containing specific terms
- Example: `sensitive documents -template`

## Ethical Usage
Google Dorks are powerful tools that should be used responsibly:

- **DO** use for:
  - Finding information about your own organization
  - Security research with proper authorization
  - OSINT for legitimate investigations
  
- **DON'T** use for:
  - Accessing unauthorized systems
  - Finding personal information to harass individuals
  - Any illegal activities

## Using Dorks Safely
- Always have proper authorization before probing any organization
- Document your activities when conducting security research
- Report vulnerabilities responsibly if discovered
- Consider legal implications in your jurisdiction

## RustVault's Dork Builder
RustVault's Dork Builder helps you create effective search queries while maintaining ethical boundaries. Use it to assess your own organization's digital footprint or for legitimate research.

Remember: With great power comes great responsibility. Use these tools ethically and legally.
"#.to_string(),
            category: "OSINT Tools".to_string(),
            difficulty: "intermediate".to_string(),
            related_topics: vec!["osint_basics".to_string(), "information_leakage".to_string()],
        });
        
        Self { topics }
    }
    
    pub fn get_all_topics(&self) -> Vec<crate::api::types::EducationTopic> {
        self.topics.values()
            .map(|t| crate::api::types::EducationTopic {
                id: t.id.clone(),
                title: t.title.clone(),
                description: t.content.lines().nth(0).unwrap_or("").trim_start_matches("# ").to_string(),
                category: t.category.clone(),
                difficulty: t.difficulty.clone(),
            })
            .collect()
    }
    
    pub fn get_topic_by_id(&self, id: &str) -> Option<crate::api::types::TopicContent> {
        self.topics.get(id).map(|t| crate::api::types::TopicContent {
            id: t.id.clone(),
            title: t.title.clone(),
            content: t.content.clone(),
            category: t.category.clone(),
            difficulty: t.difficulty.clone(),
            related_topics: t.related_topics.clone(),
        })
    }
}