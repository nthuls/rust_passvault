// src/cli/mod.rs
use clap::{Parser};

pub mod commands;
pub mod menu;
pub mod handlers;

pub use commands::CliCommand;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Use JSON for input/output (for API use)
    #[arg(long)]
    pub json: bool,
    
    /// Database URL
    #[arg(long, short, env = "DATABASE_URL", default_value = "sqlite:./data/securevault.db")]
    pub db: String,
    
    /// Command to execute
    #[command(subcommand)]
    pub command: Option<CliCommand>,

    /// Skip starting the API server
    #[arg(long)]
    pub no_api: bool,
    
    /// API server port
    #[arg(long)]
    pub api_port: Option<u16>,
    
    /// Run in API-only mode (no CLI)
    #[arg(long)]
    pub api_only: bool,

}