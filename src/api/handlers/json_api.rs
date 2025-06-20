// src/api/handlers/json_api.rs
use crate::cli::Args;
use crate::cli::CliCommand;
use crate::db::Database;
use crate::core::vault::Vault;
use std::error::Error;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::importers::firefox::FirefoxImporter;
use log::{info, error};
use crate::generators::PasswordGenerator;
use crate::models::PasswordGenerationOptions;
use std::sync::Arc;
use crate::importers::ChromeImporter;
use crate::importers::EdgeImporter;

/// Handle JSON API requests from CLI
/// 
/// This function processes CLI commands when the --json flag is used,
/// executes the appropriate command, and returns results in JSON format.
pub async fn handle_json_api(args: Args, db: Database) -> Result<(), Box<dyn Error>> {
    // Create a vault instance with Arc<Database>
    let db_arc = Arc::new(db);
    let vault = Vault::new(db_arc);
    
    // Process the command
    match args.command {
        Some(CliCommand::Unlock) => {
            // Read the master password from stdin
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            password = password.trim().to_string();
            
            // Attempt to unlock the vault
            match vault.unlock(&password).await {
                Ok(token) => {
                    let response = json!({
                        "success": true,
                        "token": token,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to unlock vault: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::List) => {
            // Read token from stdin
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            token = token.trim().to_string();
            
            // Get all passwords
            match vault.get_all_passwords(&token).await {
                Ok(passwords) => {
                    let response = json!({
                        "success": true,
                        "passwords": passwords,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to list passwords: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::Get { id }) => {
            // Read token from stdin
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            token = token.trim().to_string();
            
            // Parse UUID
            let uuid = match Uuid::parse_str(&id) {
                Ok(uuid) => uuid,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Invalid UUID format: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Get password by ID
            match vault.get_password_by_id(&token, uuid).await {
                Ok(password) => {
                    let response = json!({
                        "success": true,
                        "password": password,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to get password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::GetWithMaster { id }) => {
            // Read master password from stdin
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            password = password.trim().to_string();
            
            // Attempt to unlock the vault
            let token = match vault.unlock(&password).await {
                Ok(token) => token,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to unlock vault: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Parse UUID
            let uuid = match Uuid::parse_str(&id) {
                Ok(uuid) => uuid,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Invalid UUID format: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Get password by ID
            match vault.get_password_by_id(&token, uuid).await {
                Ok(password) => {
                    let response = json!({
                        "success": true,
                        "password": password,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to get password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::Add) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract values
            let token = json_data["token"].as_str().ok_or("Missing token")?;
            let site = json_data["site"].as_str().ok_or("Missing site")?;
            let username = json_data["username"].as_str().ok_or("Missing username")?;
            let password = json_data["password"].as_str().ok_or("Missing password")?;
            let notes = json_data["notes"].as_str();
            
            // Extract categories
            let categories = if json_data["categories"].is_array() {
                json_data["categories"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect::<Vec<String>>()
            } else {
                Vec::new()
            };
            
            // Add the password
            match vault.add_password(token, site, username, password, notes, &categories).await {
                Ok(id) => {
                    let response = json!({
                        "success": true,
                        "id": id.to_string(),
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to add password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::AddWithMaster) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract master password
            let master_password = json_data["master_password"].as_str().ok_or("Missing master password")?;
            // Unlock the vault
            let token = match vault.unlock(master_password).await {
                Ok(token) => token,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to unlock vault: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Extract values for the new password
            let site = json_data["site"].as_str().ok_or("Missing site")?;
            let username = json_data["username"].as_str().ok_or("Missing username")?;
            let password = json_data["password"].as_str().ok_or("Missing password")?;
            let notes = json_data["notes"].as_str();
            
            // Extract categories
            let categories = if json_data["categories"].is_array() {
                json_data["categories"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect::<Vec<String>>()
            } else {
                Vec::new()
            };
            
            // Add the password
            match vault.add_password(&token, site, username, password, notes, &categories).await {
                Ok(id) => {
                    let response = json!({
                        "success": true,
                        "id": id.to_string(),
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to add password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::Delete { id }) => {
            // Read token from stdin
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            token = token.trim().to_string();
            
            // Parse UUID
            let uuid = match Uuid::parse_str(&id) {
                Ok(uuid) => uuid,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Invalid UUID format: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Delete the password
            match vault.delete_password(&token, uuid).await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": "Password deleted successfully",
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to delete password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::UpdateWithMaster) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract master password
            let master_password = json_data["master_password"].as_str().ok_or("Missing master password")?;
            
            // Unlock the vault
            let token = match vault.unlock(master_password).await {
                Ok(token) => token,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to unlock vault: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Extract password ID
            let id_str = json_data["id"].as_str().ok_or("Missing password ID")?;
            let id = match Uuid::parse_str(id_str) {
                Ok(uuid) => uuid,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Invalid UUID format: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Extract optional values
            let site = json_data["site"].as_str();
            let username = json_data["username"].as_str();
            let password = json_data["password"].as_str();
            let notes = json_data["notes"].as_str();
            
            // Extract categories if present
            let categories = if json_data["categories"].is_array() {
                Some(
                    json_data["categories"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect::<Vec<String>>()
                )
            } else {
                None
            };
            
            // Update the password
            match vault.update_password(
                &token, 
                id, 
                site, 
                username, 
                password, 
                notes, 
                categories.as_deref()
            ).await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": "Password updated successfully",
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to update password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        Some(CliCommand::Import { source, path, password, category }) => {
            // Read token from stdin
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            token = token.trim().to_string();
            
            match source.to_lowercase().as_str() {
                "firefox" => {
                    // Create the Firefox importer
                    let firefox_importer = FirefoxImporter::new();
                    
                    // Get the database reference
                    let db = vault.get_db_ref();
                    
                    // We need to get the encryption key from the vault
                    // Since we likely can't access the key directly, we'll use the token to perform
                    // the import operation through the vault
                    match vault.import_firefox_passwords(
                        &token,
                        path.as_deref(),
                        password.as_deref(),
                        category.as_deref(),
                    ).await {
                        Ok(count) => {
                            info!("Successfully imported {} passwords from Firefox", count);
                            let response = json!({
                                "success": true,
                                "count": count,
                                "message": format!("Successfully imported {} passwords from Firefox", count),
                            });
                            println!("{}", response);
                        },
                        Err(e) => {
                            error!("Failed to import Firefox credentials: {}", e);
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to import Firefox credentials: {}", e),
                            });
                            println!("{}", response);
                        }
                    }
                },
                // This code should be integrated into your CLI JSON API handler
                // Add these blocks to the match statement in src/api/handlers/json_api.rs
                // For Chrome import
                "chrome" => {
                    // Create the Chrome importer
                    let chrome_importer = ChromeImporter::new();
                    
                    // Get the database reference
                    let db = vault.get_db_ref();
                    
                    // We need to get the encryption key from the vault
                    let session_id = match vault.auth_manager.validate_token(&token) {
                        Ok(sid) => sid,
                        Err(e) => {
                            let response = json!({
                                "success": false,
                                "error": format!("Invalid session token: {}", e),
                            });
                            println!("{}", response);
                            return Ok(());
                        }
                    };
                    
                    // Get the master key
                    let master_key = match vault.auth_manager.get_master_key(&session_id) {
                        Ok(key) => key,
                        Err(e) => {
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to get master key: {}", e),
                            });
                            println!("{}", response);
                            return Ok(());
                        }
                    };
                    
                    // Import the credentials
                    match chrome_importer.import_passwords(
                        &db,
                        path.as_deref(),
                        &master_key,
                        category.as_deref(),
                        Some(false), // Add this parameter - default to not updating
                    ).await {
                        Ok((added, updated)) => {
                            let total = added + updated;
                            info!("Successfully imported {} passwords from Chrome ({} new, {} updated)", 
                                  total, added, updated);
                            let response = json!({
                                "success": true,
                                "count": total,
                                "added_count": added,
                                "updated_count": updated,
                                "message": format!("Successfully imported {} passwords from Chrome ({} new, {} updated)", 
                                                  total, added, updated),
                            });
                            println!("{}", response);
                        },
                        Err(e) => {
                            error!("Failed to import Chrome credentials: {}", e);
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to import Chrome credentials: {}", e),
                            });
                            println!("{}", response);
                        }
                    }
                },
                "edge" => {
                    // Create the Edge importer
                    let edge_importer = EdgeImporter::new();
                    
                    // Get the database reference
                    let db = vault.get_db_ref();
                    
                    // We need to get the encryption key from the vault
                    let session_id = match vault.auth_manager.validate_token(&token) {
                        Ok(sid) => sid,
                        Err(e) => {
                            let response = json!({
                                "success": false,
                                "error": format!("Invalid session token: {}", e),
                            });
                            println!("{}", response);
                            return Ok(());
                        }
                    };
                    
                    // Get the master key
                    let master_key = match vault.auth_manager.get_master_key(&session_id) {
                        Ok(key) => key,
                        Err(e) => {
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to get master key: {}", e),
                            });
                            println!("{}", response);
                            return Ok(());
                        }
                    };
                    
                    // Import the credentials
                    match edge_importer.import_passwords(
                        &db,
                        path.as_deref(),
                        &master_key,
                        category.as_deref(),
                        Some(false), // Add this parameter - default to not updating
                    ).await {
                        Ok((added, updated)) => {
                            let total = added + updated;
                            info!("Successfully imported {} passwords from Edge ({} new, {} updated)", 
                                  total, added, updated);
                            let response = json!({
                                "success": true,
                                "count": total,
                                "added_count": added,
                                "updated_count": updated,
                                "message": format!("Successfully imported {} passwords from Edge ({} new, {} updated)", 
                                                  total, added, updated),
                            });
                            println!("{}", response);
                        },
                        Err(e) => {
                            error!("Failed to import Edge credentials: {}", e);
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to import Edge credentials: {}", e),
                            });
                            println!("{}", response);
                        }
                    }
                },
                "csv" => {
                    // CSV import requires the Web API interface for now
                    let response = json!({
                        "success": false,
                        "error": "CSV import is only supported through the web API",
                    });
                    println!("{}", response);
                },
                _ => {
                    let response = json!({
                        "success": false,
                        "error": format!("Unsupported import source: {}", source),
                    });
                    println!("{}", response);
                }
            }
        },
        Some(CliCommand::ImportWithMaster { source }) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract master password
            let master_password = json_data["master_password"].as_str().ok_or("Missing master password")?;
            
            // Extract import details
            let path = json_data["path"].as_str();
            let source_password = json_data["source_password"].as_str();
            let category = json_data["category"].as_str();
            
            // Unlock the vault
            let token = match vault.unlock(master_password).await {
                Ok(token) => token,
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to unlock vault: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            match source.to_lowercase().as_str() {
                "firefox" => {
                    // Create the Firefox importer and perform import through the vault
                    match vault.import_firefox_passwords(
                        &token,
                        path, 
                        source_password,
                        category,
                    ).await {
                        Ok(count) => {
                            info!("Successfully imported {} passwords from Firefox", count);
                            let response = json!({
                                "success": true,
                                "count": count,
                                "message": format!("Successfully imported {} passwords from Firefox", count),
                            });
                            println!("{}", response);
                        },
                        Err(e) => {
                            error!("Failed to import Firefox credentials: {}", e);
                            let response = json!({
                                "success": false,
                                "error": format!("Failed to import Firefox credentials: {}", e),
                            });
                            println!("{}", response);
                        }
                    }
                },
                // Rest of the code remains the same
                "chrome" => {
                    // Chrome import not implemented yet
                    let response = json!({
                        "success": false,
                        "error": "Chrome import not yet implemented",
                    });
                    println!("{}", response);
                },
                "edge" => {
                    // Edge import not implemented yet
                    let response = json!({
                        "success": false,
                        "error": "Edge import not yet implemented",
                    });
                    println!("{}", response);
                },
                "csv" => {
                    // CSV import requires the Web API interface for now
                    let response = json!({
                        "success": false,
                        "error": "CSV import is only supported through the web API",
                    });
                    println!("{}", response);
                },
                _ => {
                    let response = json!({
                        "success": false,
                        "error": format!("Unsupported import source: {}", source),
                    });
                    println!("{}", response);
                }
            }
        },     
        Some(CliCommand::ListProfiles) => {
            // List Firefox profiles
            let firefox_importer = FirefoxImporter::new();
            match firefox_importer.get_available_profiles() {
                Ok(profiles) => {
                    let profile_entries = profiles.iter()
                        .map(|(name, path)| json!({
                            "name": name,
                            "path": path.to_string_lossy(),
                        }))
                        .collect::<Vec<Value>>();
                    
                    let response = json!({
                        "success": true,
                        "profiles": profile_entries,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to list Firefox profiles: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::GeneratePassword) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract generation options
            let length = json_data["length"].as_u64().unwrap_or(16) as usize;
            let include_uppercase = json_data["include_uppercase"].as_bool().unwrap_or(true);
            let include_lowercase = json_data["include_lowercase"].as_bool().unwrap_or(true);
            let include_numbers = json_data["include_numbers"].as_bool().unwrap_or(true);
            let include_symbols = json_data["include_symbols"].as_bool().unwrap_or(true);
            let exclude_similar = json_data["exclude_similar"].as_bool().unwrap_or(false);
            let memorable = json_data["memorable"].as_bool().unwrap_or(false);
            
            // Create options
            let options = PasswordGenerationOptions {
                length,
                include_uppercase,
                include_lowercase,
                include_numbers,
                include_symbols,
                exclude_similar,
                memorable,
            };
            
            // Generate password
            let generator = PasswordGenerator::new();
            match generator.generate_password(&options) {
                Ok(password) => {
                    // Analyze strength
                    let strength = generator.analyze_password_strength(&password);
                    
                    let response = json!({
                        "success": true,
                        "password": password,
                        "strength": strength,
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to generate password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        Some(CliCommand::WebPassword) => {
            // Read JSON input from stdin
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            
            // Parse JSON
            let json_data: Value = serde_json::from_str(&input)?;
            
            // Extract values
            let token = json_data["token"].as_str().ok_or("Missing token")?;
            let password = json_data["password"].as_str().ok_or("Missing password")?;
            
            // Get database reference
            let db = vault.get_db_ref();
            
            // Generate password hash
            use argon2::{
                password_hash::{rand_core::OsRng, SaltString},
                Argon2, PasswordHasher,
            };
            
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
                Ok(hash) => hash.to_string(),
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to hash password: {}", e),
                    });
                    println!("{}", response);
                    return Ok(());
                }
            };
            
            // Store the hash in the database
            match db.store_config_value("web_password", &password_hash).await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": "Web password set successfully",
                    });
                    println!("{}", response);
                },
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Failed to store web password: {}", e),
                    });
                    println!("{}", response);
                }
            }
        },
        
        None => {
            // No command specified
            let response = json!({
                "success": false,
                "error": "No command specified",
            });
            println!("{}", response);
        }
    }
    
    Ok(())
}