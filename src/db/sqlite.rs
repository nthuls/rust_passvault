// src/db/sqlite.rs
use sqlx::{sqlite::{SqlitePool, SqlitePoolOptions}, Row};
use uuid::Uuid;
use std::collections::HashSet;
use std::path::Path;
use chrono::{DateTime, Utc};

use crate::models::{PasswordEntry, Category, PasswordFilter};
use super::{DatabaseBackend, DbError, Transaction};

#[derive(Debug, Clone)]
pub struct SqliteBackend {
    pool: Option<SqlitePool>,
    connection_string: Option<String>,
}

impl SqliteBackend {
    pub fn new() -> Self {
        Self {
            pool: None,
            connection_string: None,
        }
    }
    
    // Helper to get the pool or return an error
    fn get_pool(&self) -> Result<&SqlitePool, DbError> {
        self.pool.as_ref().ok_or(DbError::InitError("Database not initialized".into()))
    }

    // Add this method to get the database path
    pub fn get_db_path(&self) -> Option<String> {
        self.connection_string.as_ref().map(|conn_str| {
            if conn_str.starts_with("sqlite:") {
                conn_str[7..].to_string()
            } else {
                conn_str.clone()
            }
        })
    }
}

impl DatabaseBackend for SqliteBackend {
    async fn init(&mut self, connection_string: &str) -> Result<(), DbError> {
        // Store the connection string
        self.connection_string = Some(connection_string.to_string());
        
        // Parse the SQLite connection string
        let db_path = if connection_string.starts_with("sqlite:") {
            &connection_string[7..]
        } else {
            return Err(DbError::ConfigError("Invalid SQLite connection string".into()));
        };
        
        // Create the database directory if it doesn't exist
        if let Some(parent) = Path::new(db_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| 
                    DbError::InitError(format!("Failed to create database directory: {}", e))
                )?;
            }
        }
        
        log::info!("Initializing SQLite database at: {}", db_path);
        
        // Create a connection pool
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&format!("sqlite:{}", db_path))
            .await?;
        
        // Enable foreign keys
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&pool)
            .await?;
        
        // Create passwords table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passwords (
                id TEXT PRIMARY KEY,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;
        
        // Create categories table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS categories (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            );
            "#,
        )
        .execute(&pool)
        .await?;
        
        // Create relationship table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS password_categories (
                password_id TEXT NOT NULL,
                category_id TEXT NOT NULL,
                PRIMARY KEY (password_id, category_id),
                FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE,
                FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&pool)
        .await?;
        
        // Create config table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;
        
        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_passwords_site ON passwords(site);")
            .execute(&pool)
            .await?;
        
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_password_categories ON password_categories(password_id);")
            .execute(&pool)
            .await?;
        
        self.pool = Some(pool);
        Ok(())
    }

    async fn add_password(
        &self, 
        site: &str, 
        username: &str, 
        encrypted_password: &[u8], 
        notes: Option<&str>, 
        categories: &[String]
    ) -> Result<Uuid, DbError> {
        let pool = self.get_pool()?;
        
        // Generate a new UUID
        let password_id = Uuid::new_v4();
        
        // Get current time
        let now = chrono::Utc::now();
        let now_str = now.to_rfc3339();
        
        // Start a transaction
        let mut tx = pool.begin().await?;
        
        // Insert password - Note the use of &mut *tx instead of &mut tx
        sqlx::query(
            r#"
            INSERT INTO passwords (id, site, username, password, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(password_id.to_string())
        .bind(site)
        .bind(username)
        .bind(encrypted_password)
        .bind(notes)
        .bind(&now_str)
        .bind(&now_str)
        .execute(&mut *tx)
        .await?;
        
        // Add categories
        for category_name in categories {
            // Get or create category
            let category_id = self.get_or_create_category(category_name).await?;
            
            // Link password to category
            sqlx::query(
                r#"
                INSERT INTO password_categories (password_id, category_id)
                VALUES (?, ?)
                "#,
            )
            .bind(password_id.to_string())
            .bind(category_id.to_string())
            .execute(&mut *tx)
            .await?;
        }
        
        // Commit transaction
        tx.commit().await?;
        
        Ok(password_id)
    }

    async fn get_all_passwords(&self) -> Result<Vec<PasswordEntry>, DbError> {
        let pool = self.get_pool()?;
        
        // Get all passwords
        let password_rows = sqlx::query(
            r#"
            SELECT id, site, username, password, notes, created_at, updated_at
            FROM passwords
            ORDER BY site ASC
            "#,
        )
        .fetch_all(pool)
        .await?;
        
        let mut passwords = Vec::new();
        
        // Process each password
        for row in password_rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid UUID: {}", e)))?;
            
            let created_at_str: String = row.get("created_at");
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            let updated_at_str: String = row.get("updated_at");
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            // Get categories for this password
            let categories: Vec<String> = sqlx::query(
                r#"
                SELECT c.name
                FROM categories c
                JOIN password_categories pc ON c.id = pc.category_id
                WHERE pc.password_id = ?
                "#,
            )
            .bind(&id_str)
            .fetch_all(pool)
            .await?
            .iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
            
            passwords.push(PasswordEntry {
                id,
                site: row.get("site"),
                username: row.get("username"),
                password: row.get("password"),
                notes: row.get("notes"),
                created_at,
                updated_at,
                categories,
            });
        }
        
        Ok(passwords)
    }

    async fn get_filtered_passwords(&self, filter: &PasswordFilter) -> Result<Vec<PasswordEntry>, DbError> {
        let pool = self.get_pool()?;
        
        // Build query based on filter
        let mut query_parts = Vec::new();
        let mut params = Vec::new();
        
        query_parts.push("SELECT p.id, p.site, p.username, p.password, p.notes, p.created_at, p.updated_at FROM passwords p".to_string());
        
        if let Some(category) = &filter.category {
            query_parts.push("JOIN password_categories pc ON p.id = pc.password_id".to_string());
            query_parts.push("JOIN categories c ON pc.category_id = c.id".to_string());
            query_parts.push("WHERE c.name = ?".to_string());
            params.push(category.clone());
        }
        
        let mut where_added = filter.category.is_some();
        
        if let Some(site) = &filter.site_contains {
            if where_added {
                query_parts.push("AND p.site LIKE ?".to_string());
            } else {
                query_parts.push("WHERE p.site LIKE ?".to_string());
                where_added = true;
            }
            params.push(format!("%{}%", site));
        }
        
        if let Some(username) = &filter.username_contains {
            if where_added {
                query_parts.push("AND p.username LIKE ?".to_string());
            } else {
                query_parts.push("WHERE p.username LIKE ?".to_string());
                where_added = true;
            }
            params.push(format!("%{}%", username));
        }
        
        query_parts.push("ORDER BY p.site ASC".to_string());
        
        let query = query_parts.join(" ");
        
        // Build the query
        let mut sqlx_query = sqlx::query(&query);
        for param in &params {
            sqlx_query = sqlx_query.bind(param);
        }
        
        // Execute the query
        let rows = sqlx_query.fetch_all(pool).await?;
        
        let mut passwords = Vec::new();
        
        // Process each password row
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid UUID: {}", e)))?;
            
            let created_at_str: String = row.get("created_at");
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            let updated_at_str: String = row.get("updated_at");
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            // Get categories for this password
            let categories: Vec<String> = sqlx::query(
                r#"
                SELECT c.name
                FROM categories c
                JOIN password_categories pc ON c.id = pc.category_id
                WHERE pc.password_id = ?
                "#,
            )
            .bind(&id_str)
            .fetch_all(pool)
            .await?
            .iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
            
            passwords.push(PasswordEntry {
                id,
                site: row.get("site"),
                username: row.get("username"),
                password: row.get("password"),
                notes: row.get("notes"),
                created_at,
                updated_at,
                categories,
            });
        }
        
        Ok(passwords)
    }
    
    async fn get_password_by_id(&self, id: Uuid) -> Result<PasswordEntry, DbError> {
        let pool = self.get_pool()?;
        
        let id_str = id.to_string();
        
        let row = sqlx::query(
            r#"
            SELECT id, site, username, password, notes, created_at, updated_at
            FROM passwords
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(pool)
        .await?
        .ok_or(DbError::NotFound)?;
        
        let created_at_str: String = row.get("created_at");
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
            .with_timezone(&Utc);
        
        let updated_at_str: String = row.get("updated_at");
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
            .with_timezone(&Utc);
        
        // Get categories for this password
        let categories: Vec<String> = sqlx::query(
            r#"
            SELECT c.name
            FROM categories c
            JOIN password_categories pc ON c.id = pc.category_id
            WHERE pc.password_id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_all(pool)
        .await?
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();
        
        Ok(PasswordEntry {
            id,
            site: row.get("site"),
            username: row.get("username"),
            password: row.get("password"),
            notes: row.get("notes"),
            created_at,
            updated_at,
            categories,
        })
    }
    
    async fn update_password(
        &self,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError> {
        let pool = self.get_pool()?;
        let id_str = id.to_string();
        
        // Start a transaction
        let mut tx = pool.begin().await?;
        
        // Check if password exists
        let exists = sqlx::query("SELECT 1 FROM passwords WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        
        if !exists {
            return Err(DbError::NotFound);
        }
        
        // Update fields
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        let mut set_parts = Vec::new();
        let mut params = Vec::new();
        
        if let Some(val) = site {
            set_parts.push("site = ?");
            params.push(val.to_string());
        }
        
        if let Some(val) = username {
            set_parts.push("username = ?");
            params.push(val.to_string());
        }
        
        if encrypted_password.is_some() {
            set_parts.push("password = ?");
            // We'll bind this separately
        }
        
        if let Some(val) = notes {
            set_parts.push("notes = ?");
            params.push(val.to_string());
        }
        
        set_parts.push("updated_at = ?");
        params.push(now_str);
        
        // Build the update query
        let query = format!(
            "UPDATE passwords SET {} WHERE id = ?",
            set_parts.join(", ")
        );
        
        // Build and execute the query
        let mut sqlx_query = sqlx::query(&query);
        
        // Bind the parameters
        for param in &params {
            sqlx_query = sqlx_query.bind(param);
        }
        
        // Bind the encrypted password if present
        if let Some(password) = encrypted_password {
            sqlx_query = sqlx_query.bind(password);
        }
        
        // Bind the ID for the WHERE clause
        sqlx_query = sqlx_query.bind(&id_str);
        
        // Execute the update
        sqlx_query.execute(&mut *tx).await?;
        
        // Update categories if provided
        if let Some(categories) = categories {
            // Get current categories
            let current_categories: Vec<(String, String)> = sqlx::query(
                r#"
                SELECT c.id, c.name
                FROM categories c
                JOIN password_categories pc ON c.id = pc.category_id
                WHERE pc.password_id = ?
                "#,
            )
            .bind(&id_str)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|row| (row.get("id"), row.get("name")))
            .collect();
            
            // Determine which categories to add and remove
            let current_names: HashSet<String> = current_categories
                .iter()
                .map(|(_, name)| name.clone())
                .collect();
            
            let new_names: HashSet<String> = categories.iter().cloned().collect();
            
            // Remove categories that aren't in the new set
            for (cat_id, name) in &current_categories {
                if !new_names.contains(name) {
                    sqlx::query(
                        r#"
                        DELETE FROM password_categories
                        WHERE password_id = ? AND category_id = ?
                        "#,
                    )
                    .bind(&id_str)
                    .bind(cat_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            
            // Add new categories
            for name in new_names.iter() {
                if !current_names.contains(name) {
                    let category_id = self.get_or_create_category(name).await?;
                    
                    sqlx::query(
                        r#"
                        INSERT INTO password_categories (password_id, category_id)
                        VALUES (?, ?)
                        "#,
                    )
                    .bind(&id_str)
                    .bind(category_id.to_string())
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        
        // Commit the transaction
        tx.commit().await?;
        
        Ok(())
    }
    
    async fn delete_password(&self, id: Uuid) -> Result<(), DbError> {
        let pool = self.get_pool()?;
        let id_str = id.to_string();
        
        let result = sqlx::query("DELETE FROM passwords WHERE id = ?")
            .bind(&id_str)
            .execute(pool)
            .await?;
        
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }
        
        Ok(())
    }
    
    async fn get_all_categories(&self) -> Result<Vec<Category>, DbError> {
        let pool = self.get_pool()?;
        
        let rows = sqlx::query("SELECT id, name FROM categories ORDER BY name ASC")
            .fetch_all(pool)
            .await?;
        
        let mut categories = Vec::new();
        
        for row in rows {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid UUID: {}", e)))?;
            
            categories.push(Category {
                id,
                name: row.get("name"),
            });
        }
        
        Ok(categories)
    }
    
    async fn get_or_create_category(&self, name: &str) -> Result<Uuid, DbError> {
        let pool = self.get_pool()?;
        
        // Check if category exists
        let existing = sqlx::query("SELECT id FROM categories WHERE name = ?")
            .bind(name)
            .fetch_optional(pool)
            .await?;
        
        if let Some(row) = existing {
            let id_str: String = row.get("id");
            return Uuid::parse_str(&id_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid UUID: {}", e)));
        }
        
        // Create new category
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        
        sqlx::query("INSERT INTO categories (id, name) VALUES (?, ?)")
            .bind(&id_str)
            .bind(name)
            .execute(pool)
            .await?;
        
        Ok(id)
    }
    
    async fn delete_category(&self, id: Uuid) -> Result<(), DbError> {
        let pool = self.get_pool()?;
        let id_str = id.to_string();
        
        let result = sqlx::query("DELETE FROM categories WHERE id = ?")
            .bind(&id_str)
            .execute(pool)
            .await?;
        
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }
        
        Ok(())
    }
    
    async fn get_config_value(&self, key: &str) -> Result<Option<String>, DbError> {
        let pool = self.get_pool()?;
        
        let row = sqlx::query("SELECT value FROM config WHERE key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await?;
        
        Ok(row.map(|r| r.get("value")))
    }
    
    async fn store_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
        let pool = self.get_pool()?;
        
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        sqlx::query(
            r#"
            INSERT INTO config (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE
            SET value = ?, updated_at = ?
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(&now_str)
        .bind(value)
        .bind(&now_str)
        .execute(pool)
        .await?;
        
        Ok(())
    }
    
    async fn begin_transaction<'t>(&self) -> Result<super::Transaction<'t>, DbError> {
        let pool = self.get_pool()?;
        let tx = pool.begin().await?;
        Ok(super::Transaction::Sqlite(tx))
    }
    
    async fn commit_transaction<'t>(&self, tx: super::Transaction<'t>) -> Result<(), DbError> {
        match tx {
            super::Transaction::Sqlite(tx) => {
                tx.commit().await?;
                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for SQLite".into())),
        }
    }
    
    async fn rollback_transaction<'t>(&self, tx: super::Transaction<'t>) -> Result<(), DbError> {
        match tx {
            super::Transaction::Sqlite(tx) => {
                tx.rollback().await?;
                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for SQLite".into())),
        }
    }
    
    async fn update_password_in_transaction<'t>(
        &self,
        tx: &mut super::Transaction<'t>,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError> {
        let sqlite_tx = match tx {
            super::Transaction::Sqlite(tx) => tx,
            _ => return Err(DbError::ConfigError("Invalid transaction type for SQLite".into())),
        };
    
        let id_str = id.to_string();
        
        // Check if password exists
        let exists = sqlx::query("SELECT 1 FROM passwords WHERE id = ?")
            .bind(&id_str)
            .fetch_optional(&mut **sqlite_tx)
            .await?
            .is_some();
        
        if !exists {
            return Err(DbError::NotFound);
        }
        
        // Update fields
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        let mut set_parts = Vec::new();
        let mut params = Vec::new();
        
        if let Some(val) = site {
            set_parts.push("site = ?");
            params.push(val.to_string());
        }
        
        if let Some(val) = username {
            set_parts.push("username = ?");
            params.push(val.to_string());
        }
        
        if encrypted_password.is_some() {
            set_parts.push("password = ?");
            // We'll bind this separately
        }
        
        if let Some(val) = notes {
            set_parts.push("notes = ?");
            params.push(val.to_string());
        }
        
        set_parts.push("updated_at = ?");
        params.push(now_str);
        
        // Build the update query
        let query = format!(
            "UPDATE passwords SET {} WHERE id = ?",
            set_parts.join(", ")
        );
        
        // Build and execute the query
        let mut sqlx_query = sqlx::query(&query);
        
        // Bind the parameters
        for param in &params {
            sqlx_query = sqlx_query.bind(param);
        }
        
        // Bind the encrypted password if present
        if let Some(password) = encrypted_password {
            sqlx_query = sqlx_query.bind(password);
        }
        
        // Bind the ID for the WHERE clause
        sqlx_query = sqlx_query.bind(&id_str);
        
        // Execute the update
        sqlx_query.execute(&mut **sqlite_tx).await?;
        
        // Update categories if provided
        if let Some(categories) = categories {
            // Get current categories
            let current_categories: Vec<(String, String)> = sqlx::query(
                r#"
                SELECT c.id, c.name
                FROM categories c
                JOIN password_categories pc ON c.id = pc.category_id
                WHERE pc.password_id = ?
                "#,
            )
            .bind(&id_str)
            .fetch_all(&mut **sqlite_tx)
            .await?
            .into_iter()
            .map(|row| (row.get("id"), row.get("name")))
            .collect();
            
            // Determine which categories to add and remove
            let current_names: HashSet<String> = current_categories
                .iter()
                .map(|(_, name)| name.clone())
                .collect();
            
            let new_names: HashSet<String> = categories.iter().cloned().collect();
            
            // Remove categories that aren't in the new set
            for (cat_id, name) in &current_categories {
                if !new_names.contains(name) {
                    sqlx::query(
                        r#"
                        DELETE FROM password_categories
                        WHERE password_id = ? AND category_id = ?
                        "#,
                    )
                    .bind(&id_str)
                    .bind(cat_id)
                    .execute(&mut **sqlite_tx)
                    .await?;
                }
            }
            
            // Add new categories
            for name in new_names.iter() {
                if !current_names.contains(name) {
                    let category_id = self.get_or_create_category(name).await?;
                    
                    sqlx::query(
                        r#"
                        INSERT INTO password_categories (password_id, category_id)
                        VALUES (?, ?)
                        "#,
                    )
                    .bind(&id_str)
                    .bind(category_id.to_string())
                    .execute(&mut **sqlite_tx)
                    .await?;
                }
            }
        }
        
        Ok(())
    }

    async fn restore_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        password: PasswordEntry,
    ) -> Result<(), DbError> {
        // Match the transaction type
        let sqlite_tx = match tx {
            Transaction::Sqlite(tx) => tx,
            _ => return Err(DbError::ConfigError("Invalid transaction type for SQLite".into())),
        };

        // First check if password already exists with this ID
        let pool = self.get_pool()?;
        
        let existing = sqlx::query(
            "SELECT COUNT(*) as count FROM passwords WHERE id = ?"
        )
        .bind(password.id.to_string())
        .fetch_one(pool)
        .await?;

        let count: i64 = existing.try_get("count")?;

        if count > 0 {
            // Password already exists, update it
            self.update_password_in_transaction(
                tx,
                password.id,
                Some(&password.site),
                Some(&password.username),
                Some(&password.password),
                password.notes.as_deref(),
                Some(&password.categories),
            )
            .await
        } else {
            // Password doesn't exist, insert it with the original ID
            sqlx::query(
                "INSERT INTO passwords (id, site, username, password, notes, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(password.id.to_string())
            .bind(&password.site)
            .bind(&password.username)
            .bind(&password.password)
            .bind(&password.notes)
            .bind(password.created_at.to_rfc3339())
            .bind(password.updated_at.to_rfc3339())
            .execute(&mut **sqlite_tx)
            .await?;

            // Add categories
            for category in &password.categories {
                let category_id = self.get_or_create_category(category).await?;

                sqlx::query(
                    "INSERT OR IGNORE INTO password_categories (password_id, category_id)
                     VALUES (?, ?)"
                )
                .bind(password.id.to_string())
                .bind(category_id.to_string())
                .execute(&mut **sqlite_tx)
                .await?;
            }

            Ok(())
        }
    }

    async fn store_config_value_in_transaction<'t>(
        &self,
        tx: &mut super::Transaction<'t>,
        key: &str,
        value: &str,
    ) -> Result<(), DbError> {
        let sqlite_tx = match tx {
            super::Transaction::Sqlite(tx) => tx,
            _ => return Err(DbError::ConfigError("Invalid transaction type for SQLite".into())),
        };
        
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        
        sqlx::query(
            r#"
            INSERT INTO config (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE
            SET value = ?, updated_at = ?
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(&now_str)
        .bind(value)
        .bind(&now_str)
        .execute(&mut **sqlite_tx) // Changed to &mut **sqlite_tx
        .await?;
        
        Ok(())
    }
    async fn get_password_count(&self) -> Result<usize, DbError> {
        let pool = self.get_pool()?;
        let result = sqlx::query("SELECT COUNT(*) as count FROM passwords")
            .fetch_one(pool)
            .await?;
        Ok(result.get::<i64, _>("count") as usize)
    }

    async fn get_password_by_site_and_username(
        &self,
        site: &str,
        username: &str
    ) -> Result<Option<PasswordEntry>, DbError> {
        let pool = self.get_pool()?;
        
        // Use query instead of query_as since we need to manually construct the PasswordEntry
        let row = sqlx::query(
            "SELECT id, site, username, password, notes, created_at, updated_at
             FROM passwords
             WHERE site = ? AND username = ?"
        )
        .bind(site)
        .bind(username)
        .fetch_optional(pool)
        .await?;
        
        if let Some(row) = row {
            let id_str: String = row.get("id");
            let id = Uuid::parse_str(&id_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid UUID: {}", e)))?;
                
            let created_at_str: String = row.get("created_at");
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            let updated_at_str: String = row.get("updated_at");
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|e| DbError::SqlxError(format!("Invalid datetime: {}", e)))?
                .with_timezone(&Utc);
            
            // Get categories for this password
            let categories = sqlx::query(
                "SELECT c.name
                 FROM categories c
                 JOIN password_categories pc ON c.id = pc.category_id
                 WHERE pc.password_id = ?"
            )
            .bind(&id_str)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|r| r.get::<String, _>("name"))
            .collect();
            
            let password_entry = PasswordEntry {
                id,
                site: row.get("site"),
                username: row.get("username"),
                password: row.get("password"),
                notes: row.get("notes"),
                created_at,
                updated_at,
                categories,
            };
            
            Ok(Some(password_entry))
        } else {
            Ok(None)
        }
    }

    async fn add_or_update_password(
        &self, 
        site: &str, 
        username: &str, 
        encrypted_password: &[u8], 
        notes: Option<&str>, 
        categories: &[String],
        update_if_exists: bool
    ) -> Result<(Uuid, bool), DbError> {
        // Check if the password already exists
        let existing_password = self.get_password_by_site_and_username(site, username).await?;
        
        match existing_password {
            Some(existing) if update_if_exists => {
                // Update the existing password
                self.update_password(
                    existing.id,
                    Some(site),
                    Some(username),
                    Some(encrypted_password),
                    notes,
                    Some(categories),
                ).await?;
                
                Ok((existing.id, true)) // Password was updated
            },
            Some(existing) => {
                // Password exists but we're not updating
                Ok((existing.id, false)) // Password was not updated (skipped)
            },
            None => {
                // Add new password
                let id = self.add_password(site, username, encrypted_password, notes, categories).await?;
                Ok((id, false)) // New password was added
            }
        }
    }
}