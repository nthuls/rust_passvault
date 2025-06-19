// src/cli/commands.rs
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Unlock the vault
    Unlock,
    
    /// List all passwords
    List,
    
    /// Add a password
    Add,
    
    /// Add a password with master password
    AddWithMaster,
    
    /// Get a password by ID
    Get {
        /// Password ID
        #[arg(required = true)]
        id: String,
    },
    
    /// Get a password by ID with master password
    GetWithMaster {
        /// Password ID
        #[arg(required = true)]
        id: String,
    },
    
    /// Update a password with master password
    UpdateWithMaster,
    
    /// Delete a password
    Delete {
        /// Password ID
        #[arg(required = true)]
        id: String,
    },
    
    /// Import passwords from a source
    Import {
        /// Source to import from
        #[arg(required = true)]
        source: String,
        
        /// Path to the source (e.g., Firefox profile path)
        #[arg(long)]
        path: Option<String>,
        
        /// Master password for the source (if required)
        #[arg(long)]
        password: Option<String>,
        
        /// Category to assign to imported passwords
        #[arg(long)]
        category: Option<String>,
    },
    
    /// Import passwords from a source with master password
    ImportWithMaster {
        /// Source to import from
        #[arg(required = true)]
        source: String,
    },
    
    /// List available Firefox profiles
    ListProfiles,
    
    /// Generate a password
    GeneratePassword,
    
    /// Set up or change the web interface password
    WebPassword,
}