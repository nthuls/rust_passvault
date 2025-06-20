// src/db/postgres.rs
use sqlx::{postgres::PgPoolOptions, PgPool, Row, types::Uuid};
use std::collections::HashSet;
use sqlx::postgres::PgRow;

use crate::models::{PasswordEntry, Category, PasswordFilter};
use super::{DatabaseBackend, DbError, Transaction};

#[derive(Debug, Clone)]
pub struct PostgresBackend {
    pool: Option<PgPool>,
}

impl PostgresBackend {
    pub fn new() -> Self {
        Self {
            pool: None,
        }
    }
    
    // Helper to get the pool or return an error
    fn get_pool(&self) -> Result<&PgPool, DbError> {
        self.pool.as_ref().ok_or(DbError::InitError("Database not initialized".into()))
    }
}

impl DatabaseBackend for PostgresBackend {
    async fn init(&mut self, connection_string: &str) -> Result<(), DbError> {
        log::info!("Initializing PostgreSQL database...");
        
        // Create a connection pool
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(connection_string)
            .await?;
        
        log::info!("Connected to PostgreSQL");

        // Create config table for storing authentication data
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // Ensure the tables exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passwords (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password BYTEA NOT NULL,
                notes TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
            "#,
        )
        .execute(&pool)
        .await?;
        
        // Create categories table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS categories (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
                password_id UUID REFERENCES passwords(id) ON DELETE CASCADE,
                category_id UUID REFERENCES categories(id) ON DELETE CASCADE,
                PRIMARY KEY (password_id, category_id)
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
        
        // Ensure the gen_random_uuid function exists (for PostgreSQL versions < 13)
        let result = sqlx::query("SELECT gen_random_uuid();")
            .fetch_optional(&pool)
            .await;
        
        if let Err(e) = result {
            log::warn!("gen_random_uuid() function not available: {}", e);
            // Create the extension if possible
            sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
                .execute(&pool)
                .await?;
        }
        
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
        
        // Start a transaction
        let mut tx = pool.begin().await?;
        
        // Insert password
        let password_id: Uuid = sqlx::query(
            r#"
            INSERT INTO passwords (site, username, password, notes)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            "#,
        )
        .bind(site)
        .bind(username)
        .bind(encrypted_password)
        .bind(notes)
        .fetch_one(&mut *tx)
        .await?
        .get("id");
        
        // Add categories
        for category_name in categories {
            // Get or create category
            let category_id = self.get_or_create_category(category_name).await?;
            
            // Link password to category
            sqlx::query(
                r#"
                INSERT INTO password_categories (password_id, category_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(password_id)
            .bind(category_id)
            .execute(&mut *tx)
            .await?;
        }
        
        // Commit transaction
        tx.commit().await?;
        
        Ok(password_id)
    }

    async fn get_all_passwords(&self) -> Result<Vec<PasswordEntry>, DbError> {
        let pool = self.get_pool()?;
        
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.site, p.username, p.password, p.notes, 
                p.created_at, p.updated_at,
                COALESCE(
                    (SELECT array_agg(c.name) 
                        FROM categories c
                        JOIN password_categories pc ON c.id = pc.category_id
                        WHERE pc.password_id = p.id), 
                    ARRAY[]::text[]
                ) as categories
            FROM passwords p
            ORDER BY p.site ASC
            "#,
        )
        .fetch_all(pool)
        .await?;
        
        let passwords = rows
            .iter()
            .map(|row| PasswordEntry {
                id: row.get("id"),
                site: row.get("site"),
                username: row.get("username"),
                password: row.get("password"),
                notes: row.get("notes"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                categories: row.get("categories"),
            })
            .collect();
        
        Ok(passwords)
    }
    
    async fn get_filtered_passwords(&self, filter: &PasswordFilter) -> Result<Vec<PasswordEntry>, DbError> {
        let pool = self.get_pool()?;

        let mut query = String::from(
            r#"
            SELECT p.id, p.site, p.username, p.password, p.notes, 
                   p.created_at, p.updated_at,
                   COALESCE(
                       (SELECT array_agg(c.name) 
                        FROM categories c
                        JOIN password_categories pc ON c.id = pc.category_id
                        WHERE pc.password_id = p.id), 
                       ARRAY[]::text[]
                   ) as categories
            FROM passwords p
            "#,
        );

        let mut conditions = Vec::new();
        let mut params = Vec::new();
        let mut param_idx = 1;

        if let Some(site_filter) = &filter.site_contains {
            conditions.push(format!("p.site ILIKE ${}", param_idx));
            params.push(format!("%{}%", site_filter));
            param_idx += 1;
        }

        if let Some(username_filter) = &filter.username_contains {
            conditions.push(format!("p.username ILIKE ${}", param_idx));
            params.push(format!("%{}%", username_filter));
            param_idx += 1;
        }

        if let Some(category_filter) = &filter.category {
            query.push_str(&format!(
                r#"
                JOIN password_categories pc ON p.id = pc.password_id
                JOIN categories c ON pc.category_id = c.id AND c.name = ${}
                "#,
                param_idx
            ));
            params.push(category_filter.clone());
            param_idx += 1;
        }

        if !conditions.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&conditions.join(" AND "));
        }

        query.push_str(" ORDER BY p.site ASC");

        let mut sqlx_query = sqlx::query(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let rows = sqlx_query.fetch_all(pool).await?;

        let passwords = rows
            .into_iter()
            .map(|r| PasswordEntry {
                id: r.get("id"),
                site: r.get("site"),
                username: r.get("username"),
                password: r.get("password"),
                notes: r.get("notes"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                categories: r.get("categories"),
            })
            .collect();

        Ok(passwords)
    }

    async fn get_password_by_id(&self, id: Uuid) -> Result<PasswordEntry, DbError> {
        let pool = self.get_pool()?;

        let row = sqlx::query(
            r#"
            SELECT p.id, p.site, p.username, p.password, p.notes, 
                   p.created_at, p.updated_at,
                   COALESCE(
                       (SELECT array_agg(c.name) 
                        FROM categories c
                        JOIN password_categories pc ON c.id = pc.category_id
                        WHERE pc.password_id = p.id), 
                       ARRAY[]::text[]
                   ) as categories
            FROM passwords p
            WHERE p.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(DbError::NotFound)?;

        Ok(PasswordEntry {
            id: row.get("id"),
            site: row.get("site"),
            username: row.get("username"),
            password: row.get("password"),
            notes: row.get("notes"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            categories: row.get("categories"),
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
        let mut tx = pool.begin().await?;

        let mut update_parts = Vec::new();
        let mut bind_idx = 2;

        if site.is_some() {
            update_parts.push(format!("site = ${}", bind_idx));
            bind_idx += 1;
        }
        if username.is_some() {
            update_parts.push(format!("username = ${}", bind_idx));
            bind_idx += 1;
        }
        if encrypted_password.is_some() {
            update_parts.push(format!("password = ${}", bind_idx));
            bind_idx += 1;
        }
        if notes.is_some() {
            update_parts.push(format!("notes = ${}", bind_idx));
            bind_idx += 1;
        }

        update_parts.push("updated_at = NOW()".to_string());

        let query = format!(
            "UPDATE passwords SET {} WHERE id = $1",
            update_parts.join(", ")
        );

        let mut sqlx_query = sqlx::query(&query).bind(id);

        if let Some(v) = site {
            sqlx_query = sqlx_query.bind(v);
        }
        if let Some(v) = username {
            sqlx_query = sqlx_query.bind(v);
        }
        if let Some(v) = encrypted_password {
            sqlx_query = sqlx_query.bind(v);
        }
        if let Some(v) = notes {
            sqlx_query = sqlx_query.bind(v);
        }

        let result = sqlx_query.execute(&mut *tx).await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }

        if let Some(categories) = categories {
            let current: Vec<(Uuid, String)> = sqlx::query(
                r#"
                SELECT c.id, c.name
                FROM categories c
                JOIN password_categories pc ON c.id = pc.category_id
                WHERE pc.password_id = $1
                "#
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|r| (r.get("id"), r.get("name")))
            .collect();

            let current_names: HashSet<String> = current.iter().map(|(_, n)| n.clone()).collect();
            let new_names: HashSet<String> = categories.iter().cloned().collect();

            let to_remove = current_names.difference(&new_names);
            for name in to_remove {
                if let Some((cat_id, _)) = current.iter().find(|(_, n)| n == name) {
                    sqlx::query("DELETE FROM password_categories WHERE password_id = $1 AND category_id = $2")
                        .bind(id)
                        .bind(cat_id)
                        .execute(&mut *tx)
                        .await?;
                }
            }

            for name in new_names.difference(&current_names) {
                let cat_id = self.get_or_create_category(name).await?;
                sqlx::query("INSERT INTO password_categories (password_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                    .bind(id)
                    .bind(cat_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    async fn delete_password(&self, id: Uuid) -> Result<(), DbError> {
        let pool = self.get_pool()?;

        let result = sqlx::query("DELETE FROM passwords WHERE id = $1")
            .bind(id)
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

        Ok(rows
            .into_iter()
            .map(|r| Category {
                id: r.get("id"),
                name: r.get("name"),
            })
            .collect())
    }

    async fn get_or_create_category(&self, name: &str) -> Result<Uuid, DbError> {
        let pool = self.get_pool()?;

        if let Some(row) = sqlx::query("SELECT id FROM categories WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await? 
        {
            return Ok(row.get("id"));
        }

        let id = sqlx::query("INSERT INTO categories (name) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(pool)
            .await?
            .get("id");

        Ok(id)
    }

    async fn delete_category(&self, id: Uuid) -> Result<(), DbError> {
        let pool = self.get_pool()?;

        let result = sqlx::query("DELETE FROM categories WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }

        Ok(())
    }

    async fn get_config_value(&self, key: &str) -> Result<Option<String>, DbError> {
        let pool = self.get_pool()?;

        let row = sqlx::query("SELECT value FROM config WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;

        Ok(row.map(|r| r.get("value")))
    }

    async fn store_config_value(&self, key: &str, value: &str) -> Result<(), DbError> {
        let pool = self.get_pool()?;

        sqlx::query(
            r#"
            INSERT INTO config (key, value, updated_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (key) DO UPDATE
            SET value = $2, updated_at = NOW()
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;

        Ok(())
    }
    
    // Transaction methods
    async fn begin_transaction<'t>(&self) -> Result<Transaction<'t>, DbError> {
        let pool = self.get_pool()?;
        let tx = pool.begin().await?;
        Ok(Transaction::Postgres(tx))
    }

    async fn commit_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError> {
        match tx {
            Transaction::Postgres(tx) => {
                tx.commit().await?;
                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for PostgreSQL".into())),
        }
    }

    async fn rollback_transaction<'t>(&self, tx: Transaction<'t>) -> Result<(), DbError> {
        match tx {
            Transaction::Postgres(tx) => {
                tx.rollback().await?;
                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for PostgreSQL".into())),
        }
    }

    async fn update_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        id: Uuid,
        site: Option<&str>,
        username: Option<&str>,
        encrypted_password: Option<&[u8]>,
        notes: Option<&str>,
        categories: Option<&[String]>,
    ) -> Result<(), DbError> {
        match tx {
            Transaction::Postgres(pg_tx) => {
                let mut update_parts = Vec::new();
                let mut bind_idx = 2;

                if site.is_some() {
                    update_parts.push(format!("site = ${}", bind_idx));
                    bind_idx += 1;
                }
                if username.is_some() {
                    update_parts.push(format!("username = ${}", bind_idx));
                    bind_idx += 1;
                }
                if encrypted_password.is_some() {
                    update_parts.push(format!("password = ${}", bind_idx));
                    bind_idx += 1;
                }
                if notes.is_some() {
                    update_parts.push(format!("notes = ${}", bind_idx));
                    bind_idx += 1;
                }

                update_parts.push("updated_at = NOW()".to_string());

                let query = format!(
                    "UPDATE passwords SET {} WHERE id = $1",
                    update_parts.join(", ")
                );

                let mut sqlx_query = sqlx::query(&query).bind(id);

                if let Some(v) = site {
                    sqlx_query = sqlx_query.bind(v);
                }
                if let Some(v) = username {
                    sqlx_query = sqlx_query.bind(v);
                }
                if let Some(v) = encrypted_password {
                    sqlx_query = sqlx_query.bind(v);
                }
                if let Some(v) = notes {
                    sqlx_query = sqlx_query.bind(v);
                }

                let result = sqlx_query.execute(&mut **pg_tx).await?;
                if result.rows_affected() == 0 {
                    return Err(DbError::NotFound);
                }

                if let Some(categories) = categories {
                    let current: Vec<(Uuid, String)> = sqlx::query(
                        r#"
                        SELECT c.id, c.name
                        FROM categories c
                        JOIN password_categories pc ON c.id = pc.category_id
                        WHERE pc.password_id = $1
                        "#
                    )
                    .bind(id)
                    .fetch_all(&mut **pg_tx)
                    .await?
                    .into_iter()
                    .map(|r| (r.get("id"), r.get("name")))
                    .collect();

                    let current_names: HashSet<String> = current.iter().map(|(_, n)| n.clone()).collect();
                    let new_names: HashSet<String> = categories.iter().cloned().collect();

                    let to_remove = current_names.difference(&new_names);
                    for name in to_remove {
                        if let Some((cat_id, _)) = current.iter().find(|(_, n)| n == name) {
                            sqlx::query("DELETE FROM password_categories WHERE password_id = $1 AND category_id = $2")
                                .bind(id)
                                .bind(cat_id)
                                .execute(&mut **pg_tx)
                                .await?;
                        }
                    }

                    for name in new_names.difference(&current_names) {
                        let cat_id = self.get_or_create_category(name).await?;
                        sqlx::query("INSERT INTO password_categories (password_id, category_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                            .bind(id)
                            .bind(cat_id)
                            .execute(&mut **pg_tx)
                            .await?;
                    }
                }

                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for PostgreSQL".into())),
        }
    }
    // For PostgresBackend
    async fn restore_password_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        password: PasswordEntry,
    ) -> Result<(), DbError> {
        match tx {
            Transaction::Postgres(pg_tx) => {
                // Check if password already exists
                let pool = self.get_pool()?;
                let existing = sqlx::query!(
                    "SELECT COUNT(*) as count FROM passwords WHERE id = $1",
                    password.id
                )
                .fetch_one(pool)
                .await?;

                if existing.count.unwrap_or(0) > 0 {
                    // Update existing password
                    self.update_password_in_transaction(
                        tx,
                        password.id,
                        Some(&password.site),
                        Some(&password.username),
                        Some(&password.password),
                        password.notes.as_deref(),
                        Some(&password.categories),
                    ).await
                } else {
                    // Insert new password with original ID
                    sqlx::query!(
                        "INSERT INTO passwords (id, site, username, password, notes, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7)",
                        password.id,
                        password.site,
                        password.username,
                        password.password,
                        password.notes,
                        password.created_at,
                        password.updated_at
                    )
                    .execute(&mut **pg_tx)
                    .await?;

                    // Insert into password_categories, avoid duplicate conflicts
                    for category in &password.categories {
                        let category_id = self.get_or_create_category(category).await?;

                        sqlx::query!(
                            "INSERT INTO password_categories (password_id, category_id)
                             VALUES ($1, $2)
                             ON CONFLICT DO NOTHING",
                            password.id,
                            category_id
                        )
                        .execute(&mut **pg_tx)
                        .await?;
                    }

                    Ok(())
                }
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for PostgreSQL".into())),
        }
    }
    
    async fn store_config_value_in_transaction<'t>(
        &self,
        tx: &mut Transaction<'t>,
        key: &str,
        value: &str,
    ) -> Result<(), DbError> {
        match tx {
            Transaction::Postgres(pg_tx) => {
                sqlx::query(
                    r#"
                    INSERT INTO config (key, value, updated_at)
                    VALUES ($1, $2, NOW())
                    ON CONFLICT (key) DO UPDATE
                    SET value = $2, updated_at = NOW()
                    "#,
                )
                .bind(key)
                .bind(value)
                .execute(&mut **pg_tx)
                .await?;

                Ok(())
            },
            _ => Err(DbError::ConfigError("Invalid transaction type for PostgreSQL".into())),
        }
    }
    async fn get_password_count(&self) -> Result<usize, DbError> {
        let pool = self.get_pool()?;
        let result = sqlx::query("SELECT COUNT(*) as count FROM passwords")
            .fetch_one(pool)
            .await?;
        Ok(result.get::<i64, _>("count") as usize)
    }

    // methods to chcek password duplicates
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
             WHERE site = $1 AND username = $2"
        )
        .bind(site)
        .bind(username)
        .fetch_optional(pool)
        .await?;
        
        if let Some(row) = row {
            let id: Uuid = row.get("id");
            
            // Get categories for this password
            let categories = sqlx::query(
                "SELECT c.name
                 FROM categories c
                 JOIN password_categories pc ON c.id = pc.category_id
                 WHERE pc.password_id = $1"
            )
            .bind(id)
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
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
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
