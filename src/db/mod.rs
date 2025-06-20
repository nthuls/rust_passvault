// src/db/mod.rs
use uuid::Uuid;
use crate::models::{PasswordEntry, Category, PasswordFilter};
use thiserror::Error;
use sqlx::Row;

pub mod postgres;
pub mod sqlite;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(String),
    
    #[error("Password not found")]
    NotFound,
    
    #[error("Category already exists: {0}")]
    CategoryExists(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Initialization error: {0}")]
    InitError(String),
    
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

// Convert database-specific errors to our DbError
impl From<sqlx::Error> for DbError {
    fn from(error: sqlx::Error) -> Self {
        DbError::SqlxError(error.to_string())
    }
}

// Define a Transaction enum that can work with either PostgreSQL or SQLite
pub enum Transaction<'t> {
    Postgres(sqlx::Transaction<'t, sqlx::Postgres>),
    Sqlite(sqlx::Transaction<'t, sqlx::Sqlite>),
}

// Database backend trait - to be implemented by each database type
pub trait DatabaseBackend: Send + Sync {
    // Initialize the database connection
    async fn init(&mut self, connection_string: &str) -> Result<(), DbError>;
    
    // Password operations
    async fn add_password(
        &self, 
        site: &str, 
        username: &str, 
        encrypted_password: &[u8], 
        notes: Option<&str>, 
        categories: &[String]
    ) -> Result<Uuid, DbError>;
    
    async fn get_all_passwords(&self) -> Result<Vec<PasswordEntry>, DbError>;
    
    async fn get_filtered_passwords(&self, filter: &PasswordFilter) -> Result<Vec<PasswordEntry>, DbError>;
    
    async fn get_password_by_id(&self, id: Uuid) -> Result<PasswordEntry, DbError>;
    
    async fn update_password(
        &self,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError>;
    
    async fn delete_password(&self, id: Uuid) -> Result<(), DbError>;
    
    // Category operations
    async fn get_all_categories(&self) -> Result<Vec<Category>, DbError>;
    
    async fn get_or_create_category(&self, name: &str) -> Result<Uuid, DbError>;
    
    async fn delete_category(&self, id: Uuid) -> Result<(), DbError>;
    
    // Configuration values
    async fn get_config_value(&self, key: &str) -> Result<Option<String>, DbError>;
    
    async fn store_config_value(&self, key: &str, value: &str) -> Result<(), DbError>;
    
    // Transaction methods
    async fn begin_transaction<'t>(&self) -> Result<Transaction<'t>, DbError>;
    
    async fn commit_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError>;
    
    async fn rollback_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError>;
    
    // Methods that work within a transaction
    async fn update_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError>;
    
    // Add this new method to the trait
    async fn restore_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        password: PasswordEntry,
    ) -> Result<(), DbError>;
    
    async fn store_config_value_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        key: &str,
        value: &str,
    ) -> Result<(), DbError>;
    
    async fn get_password_count(&self) -> Result<usize, DbError>;

    async fn get_password_by_site_and_username(
        &self,
        site: &str,
        username: &str
    ) -> Result<Option<PasswordEntry>, DbError>;

    async fn add_or_update_password(
        &self, 
        site: &str, 
        username: &str, 
        encrypted_password: &[u8], 
        notes: Option<&str>, 
        categories: &[String],
        update_if_exists: bool
    ) -> Result<(Uuid, bool), DbError>; // Returns (id, was_updated)
}

// Enum to hold specific backend implementations
#[derive(Debug, Clone)]
pub enum DatabaseType {
    Postgres(postgres::PostgresBackend),
    Sqlite(sqlite::SqliteBackend),
}

// The main database struct that uses the enum pattern instead of trait objects
#[derive(Clone)]
pub struct Database {
    pub backend: DatabaseType,
}

impl Database {
    // Create a new database connection, auto-detecting the best backend
    pub async fn new(connection_string: &str) -> Result<Self, DbError> {
        if connection_string.starts_with("sqlite:") {
            // Use SQLite backend
            let mut backend = sqlite::SqliteBackend::new();
            backend.init(connection_string).await?;
            Ok(Self {
                backend: DatabaseType::Sqlite(backend),
            })
        } else {
            // Default to PostgreSQL
            let mut backend = postgres::PostgresBackend::new();
            match backend.init(connection_string).await {
                Ok(_) => Ok(Self {
                    backend: DatabaseType::Postgres(backend),
                }),
                Err(e) => {
                    // If PostgreSQL fails, try SQLite as fallback
                    log::warn!("PostgreSQL connection failed: {}. Falling back to SQLite.", e);
                    let mut sqlite_backend = sqlite::SqliteBackend::new();
                    sqlite_backend.init("sqlite:securevault.db").await?;
                    Ok(Self {
                        backend: DatabaseType::Sqlite(sqlite_backend),
                    })
                }
            }
        }
    }
    
    // Delegate methods to the appropriate backend type
    pub async fn add_password(
        &self, 
        site: &str, 
        username: &str, 
        encrypted_password: &[u8], 
        notes: Option<&str>, 
        categories: &[String]
    ) -> Result<Uuid, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.add_password(site, username, encrypted_password, notes, categories).await,
            DatabaseType::Sqlite(backend) => backend.add_password(site, username, encrypted_password, notes, categories).await,
        }
    }
    
    pub async fn get_all_passwords(&self) -> Result<Vec<PasswordEntry>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_all_passwords().await,
            DatabaseType::Sqlite(backend) => backend.get_all_passwords().await,
        }
    }
    
    pub async fn get_filtered_passwords(&self, filter: &PasswordFilter) -> Result<Vec<PasswordEntry>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_filtered_passwords(filter).await,
            DatabaseType::Sqlite(backend) => backend.get_filtered_passwords(filter).await,
        }
    }
    
    pub async fn get_password_by_id(&self, id: Uuid) -> Result<PasswordEntry, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_password_by_id(id).await,
            DatabaseType::Sqlite(backend) => backend.get_password_by_id(id).await,
        }
    }
    
    pub async fn update_password(
        &self,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.update_password(id, site, username, encrypted_password, notes, categories).await,
            DatabaseType::Sqlite(backend) => backend.update_password(id, site, username, encrypted_password, notes, categories).await,
        }
    }
    
    pub async fn delete_password(&self, id: Uuid) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.delete_password(id).await,
            DatabaseType::Sqlite(backend) => backend.delete_password(id).await,
        }
    }
    
    pub async fn get_all_categories(&self) -> Result<Vec<Category>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_all_categories().await,
            DatabaseType::Sqlite(backend) => backend.get_all_categories().await,
        }
    }
    
    pub async fn get_or_create_category(&self, name: &str) -> Result<Uuid, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_or_create_category(name).await,
            DatabaseType::Sqlite(backend) => backend.get_or_create_category(name).await,
        }
    }
    
    pub async fn delete_category(&self, id: Uuid) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.delete_category(id).await,
            DatabaseType::Sqlite(backend) => backend.delete_category(id).await,
        }
    }

    pub async fn get_config_value(&self, key: &str) -> Result<Option<String>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_config_value(key).await,
            DatabaseType::Sqlite(backend) => backend.get_config_value(key).await,
        }
    }
    
    pub async fn store_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.store_config_value(key, value).await,
            DatabaseType::Sqlite(backend) => backend.store_config_value(key, value).await,
        }
    }
    
    // Transaction methods
    pub async fn begin_transaction<'t>(&self) -> Result<Transaction<'t>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.begin_transaction().await,
            DatabaseType::Sqlite(backend) => backend.begin_transaction().await,
        }
    }
    
    pub async fn commit_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.commit_transaction(tx).await,
            DatabaseType::Sqlite(backend) => backend.commit_transaction(tx).await,
        }
    }
    
    pub async fn rollback_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.rollback_transaction(tx).await,
            DatabaseType::Sqlite(backend) => backend.rollback_transaction(tx).await,
        }
    }
    
    /// Restore a password from a backup in a transaction
    pub async fn restore_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        password: PasswordEntry,
    ) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => {
                backend.restore_password_in_transaction(tx, password).await
            },
            DatabaseType::Sqlite(backend) => {
                backend.restore_password_in_transaction(tx, password).await
            },
        }
    }
    
    pub async fn update_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => {
                backend.update_password_in_transaction(tx, id, site, username, encrypted_password, notes, categories).await
            },
            DatabaseType::Sqlite(backend) => {
                backend.update_password_in_transaction(tx, id, site, username, encrypted_password, notes, categories).await
            },
        }
    }
    
    pub async fn get_password_count(&self) -> Result<usize, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_password_count().await,
            DatabaseType::Sqlite(backend) => backend.get_password_count().await,
        }
    }

    pub async fn store_config_value_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        key: &str,
        value: &str,
    ) -> Result<(), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => {
                backend.store_config_value_in_transaction(tx, key, value).await
            },
            DatabaseType::Sqlite(backend) => {
                backend.store_config_value_in_transaction(tx, key, value).await
            },
        }
    }
    pub fn get_backend_type(&self) -> &str {
        match &self.backend {
            DatabaseType::Sqlite(_) => "SQLite",
            DatabaseType::Postgres(_) => "PostgreSQL",
        }
    }

    pub fn get_sqlite_backend(&self) -> Option<&sqlite::SqliteBackend> {
        match &self.backend {
            DatabaseType::Sqlite(backend) => Some(backend),
            _ => None,
        }
    }

    pub fn get_postgres_backend(&self) -> Option<&postgres::PostgresBackend> {
        match &self.backend {
            DatabaseType::Postgres(backend) => Some(backend),
            _ => None,
        }
    }

    pub async fn get_password_by_site_and_username(
        &self,
        site: &str,
        username: &str
    ) -> Result<Option<PasswordEntry>, DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.get_password_by_site_and_username(site, username).await,
            DatabaseType::Sqlite(backend) => backend.get_password_by_site_and_username(site, username).await,
        }
    }

    pub async fn add_or_update_password(
        &self,
        site: &str,
        username: &str,
        encrypted_password: &[u8],
        notes: Option<&str>,
        categories: &[String],
        update_if_exists: bool
    ) -> Result<(Uuid, bool), DbError> {
        match &self.backend {
            DatabaseType::Postgres(backend) => backend.add_or_update_password(
                site, username, encrypted_password, notes, categories, update_if_exists
            ).await,
            DatabaseType::Sqlite(backend) => backend.add_or_update_password(
                site, username, encrypted_password, notes, categories, update_if_exists
            ).await,
        }
    }
}

// Function to initialize the database
pub async fn init_db(db_url: &str) -> Result<Database, DbError> {
    Database::new(db_url).await
}