// src/cli/menu.rs
use inquire::{Confirm, Password, Select, Text, MultiSelect};
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::db::Database;
use crate::core::vault::Vault;
use crate::models::{PasswordGenerationOptions, PasswordFilter, Category};
use crate::generators::PasswordGenerator;

pub async fn run_cli_menu(db: Database, should_exit: Arc<AtomicBool>) -> Result<(), Box<dyn Error>> {
    println!("🦀🔐 Welcome to");
    println!("╔══════════════════════════════════════╗");
    println!("║         🦀 RUSTVAULT MANAGER         ║");
    println!("╚══════════════════════════════════════╝");

    // Create vault instance using Arc<Database>
    let db_arc = Arc::new(db);
    let vault = Vault::new(db_arc);
    
    // Check if this is first-time setup
    let verification_key = "master_password_verification";
    let db_ref = vault.get_db_ref();
    let is_first_time = match db_ref.get_config_value(verification_key).await {
        Ok(None) => true,
        _ => false,
    };
    
    // Password acquisition with a single prompt based on first-time status
    let master_password = if is_first_time {
        println!("🔐 First-time setup: Creating your master password");
        
        // Get the password
        let password = Password::new("🔐 Create your master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .prompt()?;
        
        // Get the confirmation
        let confirm_password = Password::new("🔁 Confirm your master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .prompt()?;
        
        if password != confirm_password {
            println!("❌ Passwords do not match. Please try again.");
            return Ok(());
        }
        
        password
    } else {
        // Regular login - just ask for the password once
        Password::new("Enter your master password:")
            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
            .prompt()?
    };

    // Authenticate and get session token
    let token = match vault.unlock(&master_password).await {
        Ok(token) => {
            if is_first_time {
                println!("✅ Master password created and vault initialized");
                println!("\n🔒 Security recommendation: Set up account recovery options");
                
                // Ask if user wants to set up recovery options
                let setup_recovery = Confirm::new("Would you like to set up recovery options now?")
                    .with_default(true)
                    .prompt()?;
                
                if setup_recovery {
                    // Ask for recovery email
                    let setup_email = Confirm::new("Set up email recovery?")
                        .with_default(true)
                        .prompt()?;
                    
                    if setup_email {
                        let recovery_email = Text::new("Enter recovery email address:")
                            .prompt()?;
                        
                        // Store recovery email
                        db_ref.store_config_value("recovery_email", &recovery_email).await?;
                        println!("✅ Email recovery set up successfully");
                    }
                    
                    // Ask for recovery phone
                    let setup_phone = Confirm::new("Set up SMS recovery?")
                        .with_default(true)
                        .prompt()?;
                    
                    if setup_phone {
                        let recovery_phone = Text::new("Enter recovery phone number (international format, e.g., +254xxxxxxxxx):")
                            .prompt()?;
                        
                        // Store recovery phone
                        db_ref.store_config_value("recovery_phone", &recovery_phone).await?;
                        println!("✅ SMS recovery set up successfully");
                    }
                    
                    if !setup_email && !setup_phone {
                        println!("⚠️ No recovery options set up. You can set them up later through the settings menu.");
                    } else {
                        println!("✅ Recovery options set up successfully");
                    }
                } else {
                    println!("⚠️ No recovery options set up. You can set them up later through the settings menu.");
                }
            } else {
                println!("✅ Vault unlocked successfully");
            }
            token
        },
        Err(e) => {
            println!("❌ Failed to unlock vault: {}", e);
            println!("This could be due to an incorrect master password or a database issue.");
            return Ok(());
        }
    };
    
    // Create password generator
    let mut password_generator = PasswordGenerator::new();

    // Main application loop
    let mut exit_requested = false;
    while !exit_requested && !should_exit.load(Ordering::SeqCst) {
        // Main menu options
        let options = vec![
            "1️⃣  Add a new password",
            "2️⃣  View saved passwords",
            "🔍  Search passwords",
            "🗑️  Delete password",
            "🔐  Generate secure password",
            "🦊  Import from Firefox",
            "🌐  Import from Chrome",
            "🔷  Import from Edge",
            "📤  Import/Export CSV",
            "🗂️  Manage categories",
            "🔁  Change master password",
            "❌  Exit",
        ];
        
        // Use a short timeout to allow checking the exit flag
        let selection_result = tokio::task::spawn_blocking(move || {
            Select::new("Choose an option:", options)
                .with_help_message("Use arrow keys to navigate, Enter to select. Ctrl+C to exit.")
                .with_page_size(50)
                .prompt_skippable()
        }).await?;
        
        // Check if we should exit
        if should_exit.load(Ordering::SeqCst) {
            break;
        }
        
        // Process selection
        match selection_result {
            Ok(Some(selection)) => {
                match selection {
                    "1️⃣  Add a new password" => {
                        let site = Text::new("Website or service:").prompt()?;
                        let username = Text::new("Username or email:").prompt()?;

                        let generate = Confirm::new("Generate a secure password?")
                            .with_default(false)
                            .prompt()?;

                        let password = if generate {
                            let length: usize = Text::new("Password length:")
                                .with_default("16")
                                .prompt()
                                .and_then(|s| s.parse().map_err(|_| inquire::InquireError::Custom("Invalid number".into())))?;

                            let include_uppercase = Confirm::new("Include uppercase letters?")
                                .with_default(true)
                                .prompt()?;

                            let include_lowercase = Confirm::new("Include lowercase letters?")
                                .with_default(true)
                                .prompt()?;

                            let include_numbers = Confirm::new("Include numbers?")
                                .with_default(true)
                                .prompt()?;

                            let include_symbols = Confirm::new("Include symbols?")
                                .with_default(true)
                                .prompt()?;

                            let exclude_similar = Confirm::new("Exclude similar characters (like l, 1, I, O, 0)?")
                                .with_default(false)
                                .prompt()?;

                            let memorable = Confirm::new("Make password memorable?")
                                .with_default(false)
                                .prompt()?;

                            let options = PasswordGenerationOptions {
                                length,
                                include_uppercase,
                                include_lowercase,
                                include_numbers,
                                include_symbols,
                                exclude_similar,
                                memorable,
                            };

                            let generated_result = password_generator.generate_password(&options);

                            match &generated_result {
                                Ok(generated) => println!("Generated password: {}", generated),
                                Err(e) => eprintln!("Error generating password: {}", e),
                            }

                            let use_generated = Confirm::new("Use this password?")
                                .with_default(true)
                                .prompt()?;

                            if use_generated {
                                generated_result?
                            } else {
                                Password::new("Enter password:")
                                    .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                                    .prompt()?
                            }
                        } else {
                            Password::new("Enter password:")
                                .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                                .prompt()?
                        };

                        let notes = Text::new("Notes (optional):").prompt()?;
                        let notes = if notes.trim().is_empty() { None } else { Some(notes) };

                        let categories = get_categories(&vault, &token).await?;
                        let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();

                        let selected_categories = if !category_names.is_empty() {
                            MultiSelect::new("Select categories (if any):", category_names)
                                .prompt()?
                        } else {
                            Vec::new()
                        };

                        let selected_categories: Vec<String> = selected_categories.into_iter().map(String::from).collect();

                        match vault
                            .add_password(&token, &site, &username, &password, notes.as_deref(), &selected_categories)
                            .await
                        {
                            Ok(_) => println!("✅ Password added successfully!"),
                            Err(e) => println!("❌ Failed to add password: {}", e),
                        }
                    }
                    "2️⃣  View saved passwords" => {
                        // Get all passwords
                        let passwords = match vault.get_all_passwords(&token).await {
                            Ok(passwords) => passwords,
                            Err(e) => {
                                println!("❌ Failed to get passwords: {}", e);
                                continue;
                            }
                        };

                        if passwords.is_empty() {
                            println!("❗ No passwords stored yet.");
                            continue;
                        }

                        let site_display: Vec<String> = passwords
                            .iter()
                            .map(|p| format!("{} ({})", p.site, p.username))
                            .collect();
                        
                        let selection = Select::new("Select a site to view details:", site_display.clone())
                            .with_page_size(50)
                            .prompt()?;

                        // Find the selected password
                        let selected_idx = site_display.iter().position(|s| s == &selection).unwrap();
                        let selected = &passwords[selected_idx];

                        // Decrypt the password
                        let decrypted = match vault.decrypt_password(&token, &selected.password).await {
                            Ok(pwd) => pwd,
                            Err(e) => {
                                println!("❌ Failed to decrypt password: {}", e);
                                continue;
                            }
                        };

                        println!("\n🔐 Password Details");
                        println!("Site: {}", selected.site);
                        println!("Username: {}", selected.username);
                        println!("Password: {}", decrypted);
                        if let Some(notes) = &selected.notes {
                            println!("Notes: {}", notes);
                        }
                        println!("Categories: {}", selected.categories.join(", "));
                        println!("Created: {}", selected.created_at);
                        println!("Last updated: {}", selected.updated_at);
                        
                        // Password strength analysis
                        let strength = crate::crypto::analyze_password_strength(&decrypted);
                        println!("Password strength: {}/100", strength);
                        
                        // Wait for user to press enter
                        let _ = Text::new("Press enter to continue...").prompt();
                    }
                    "🔍  Search passwords" => {
                        // Get search criteria
                        let site_filter = Text::new("Site contains (optional):")
                            .prompt()?;
                        let site_filter = if site_filter.trim().is_empty() { None } else { Some(site_filter) };
                        
                        let username_filter = Text::new("Username contains (optional):")
                            .prompt()?;
                        let username_filter = if username_filter.trim().is_empty() { None } else { Some(username_filter) };
                        
                        // Get categories for filtering from the vault
                        let categories = get_categories(&vault, &token).await?;
                        let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                        
                        let category_filter = if !category_names.is_empty() {
                            let selected = Select::new("Filter by category (optional):", 
                                category_names.iter().chain(std::iter::once(&"[All Categories]")).cloned().collect::<Vec<_>>())
                                .prompt()?;
                            
                            if selected == "[All Categories]" {
                                None
                            } else {
                                Some(selected.to_string())
                            }
                        } else {
                            None
                        };
                        
                        // Create filter
                        let filter = PasswordFilter {
                            site_contains: site_filter,
                            username_contains: username_filter,
                            category: category_filter,
                        };
                        
                        // Get filtered passwords
                        let passwords = match vault.get_filtered_passwords(&token, &filter).await {
                            Ok(passwords) => passwords,
                            Err(e) => {
                                println!("❌ Failed to get passwords: {}", e);
                                continue;
                            }
                        };
                        
                        if passwords.is_empty() {
                            println!("❗ No passwords match your search criteria.");
                            continue;
                        }
                        
                        // Display results
                        println!("\n🔍 Search Results: {} passwords found", passwords.len());
                        
                        let site_display: Vec<String> = passwords
                            .iter()
                            .map(|p| format!("{} ({})", p.site, p.username))
                            .collect();
                        
                        let selection = Select::new("Select a site to view details:", site_display.clone())
                            .with_page_size(50)
                            .prompt()?;
                        
                        // Find the selected password
                        let selected_idx = site_display.iter().position(|s| s == &selection).unwrap();
                        let selected = &passwords[selected_idx];

                        // Decrypt the password
                        let decrypted = match vault.decrypt_password(&token, &selected.password).await {
                            Ok(pwd) => pwd,
                            Err(e) => {
                                println!("❌ Failed to decrypt password: {}", e);
                                continue;
                            }
                        };

                        println!("\n🔐 Password Details");
                        println!("Site: {}", selected.site);
                        println!("Username: {}", selected.username);
                        println!("Password: {}", decrypted);
                        if let Some(notes) = &selected.notes {
                            println!("Notes: {}", notes);
                        }
                        println!("Categories: {}", selected.categories.join(", "));
                        println!("Created: {}", selected.created_at);
                        println!("Last updated: {}", selected.updated_at);
                        
                        // Wait for user to press enter
                        let _ = Text::new("Press enter to continue...").prompt();
                    }
                    "🗑️  Delete password" => {
                        let passwords = match vault.get_all_passwords(&token).await {
                            Ok(passwords) => passwords,
                            Err(e) => {
                                println!("❌ Failed to get passwords: {}", e);
                                continue;
                            }
                        };

                        if passwords.is_empty() {
                            println!("❗ No passwords stored yet.");
                            continue;
                        }

                        let site_display: Vec<String> = passwords
                            .iter()
                            .map(|p| format!("{} ({})", p.site, p.username))
                            .collect();
                        
                        let selection = Select::new("Select a site to delete:", site_display.clone())
                            .with_page_size(50)
                            .prompt()?;
                        
                        // Find the selected password
                        let selected_idx = site_display.iter().position(|s| s == &selection).unwrap();
                        let selected = &passwords[selected_idx];

                        let confirm = Confirm::new(&format!("Are you sure you want to delete the entry for '{}'?", selected.site))
                            .with_default(false)
                            .prompt()?;

                        if confirm {
                            match vault.delete_password(&token, selected.id).await {
                                Ok(_) => println!("✅ Password deleted successfully!"),
                                Err(e) => println!("❌ Failed to delete password: {}", e),
                            }
                        }
                    }
                    "🔐  Generate secure password" => {
                        // Get password generation options
                        let length: usize = Text::new("Password length:")
                            .with_default("16")
                            .prompt()
                            .and_then(|s| s.parse().map_err(|_| inquire::InquireError::Custom("Invalid number".into())))?;

                        let include_uppercase = Confirm::new("Include uppercase letters?")
                            .with_default(true)
                            .prompt()?;

                        let include_lowercase = Confirm::new("Include lowercase letters?")
                            .with_default(true)
                            .prompt()?;

                        let include_numbers = Confirm::new("Include numbers?")
                            .with_default(true)
                            .prompt()?;

                        let include_symbols = Confirm::new("Include symbols?")
                            .with_default(true)
                            .prompt()?;

                        let exclude_similar = Confirm::new("Exclude similar characters (like l, 1, I, O, 0)?")
                            .with_default(false)
                            .prompt()?;

                        let memorable = Confirm::new("Make password memorable?")
                            .with_default(false)
                            .prompt()?;

                        // Generate password
                        let options = PasswordGenerationOptions {
                            length,
                            include_uppercase,
                            include_lowercase,
                            include_numbers,
                            include_symbols,
                            exclude_similar,
                            memorable,
                        };

                        match password_generator.generate_password(&options) {
                            Ok(generated) => {
                                println!("\nGenerated Password: {}", generated);
                                println!("Strength: {}/100", crate::crypto::analyze_password_strength(&generated));

                                let save = Confirm::new("Save this password?")
                                    .with_default(false)
                                    .prompt()?;

                                if save {
                                    let site = Text::new("Website or service:").prompt()?;
                                    let username = Text::new("Username or email:").prompt()?;

                                    let notes = Text::new("Notes (optional):").prompt()?;
                                    let notes = if notes.trim().is_empty() { None } else { Some(notes) };

                                    let categories = get_categories(&vault, &token).await?;
                                    let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();

                                    let selected_categories = if !category_names.is_empty() {
                                        MultiSelect::new("Select categories (if any):", category_names)
                                            .prompt()?
                                    } else {
                                        Vec::new()
                                    };

                                    let selected_categories: Vec<String> = selected_categories.into_iter().map(String::from).collect();

                                    match vault.add_password(&token, &site, &username, &generated, notes.as_deref(), &selected_categories).await {
                                        Ok(_) => println!("✅ Password saved successfully!"),
                                        Err(e) => println!("❌ Failed to save password: {}", e),
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to generate password: {}", e);
                            }
                        }

                        // Wait for user to press enter
                        let _ = Text::new("Press enter to continue...").prompt();
                    }
                    "🦊  Import from Firefox" => {
                        // Create Firefox importer
                        let importer = crate::importers::FirefoxImporter::new();
                        
                        // Find Firefox profiles
                        let profiles = importer.list_profiles();
                        
                        if profiles.is_empty() {
                            println!("❗ No Firefox profiles found.");
                            continue;
                        }
                        
                        // Display profiles for selection
                        let profile_display: Vec<String> = profiles
                            .iter()
                            .map(|(name, path)| format!("{} ({})", name, path.display()))
                            .collect();
                        
                        let selection = Select::new("Select Firefox profile:", profile_display.clone())
                            .with_page_size(50)
                            .prompt()?;
                        
                        // Find the selected profile
                        let selected_idx = profile_display.iter().position(|s| s == &selection).unwrap();
                        let (_, profile_path) = &profiles[selected_idx];
                        
                        // Ask for Firefox master password if needed
                        let use_master = Confirm::new("Does this Firefox profile use a master password?")
                            .with_default(false)
                            .prompt()?;
                        
                        let firefox_master_pass = if use_master {
                            Some(Password::new("Firefox master password:")
                                .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                                .prompt()?)
                        } else {
                            None
                        };
                        
                        // Choose category for imported passwords
                        let categories = get_categories(&vault, &token).await?;
                        let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                        
                        let category = if !category_names.is_empty() {
                            let selected = Select::new("Add imported passwords to category:", 
                                category_names.iter().chain(std::iter::once(&"[No Category]")).cloned().collect::<Vec<_>>())
                                .prompt()?;
                            
                            if selected == "[No Category]" {
                                None
                            } else {
                                Some(selected)
                            }
                        } else {
                            None
                        };
                        
                        // Import passwords
                        println!("Importing passwords from Firefox...");
                        
                        // Get the session ID and master key for importing
                        let session_id = match vault.auth_manager.validate_token(&token) {
                            Ok(sid) => sid,
                            Err(e) => {
                                println!("❌ Authentication error: {}", e);
                                continue;
                            }
                        };
                        
                        let master_key = match vault.auth_manager.get_master_key(&session_id) {
                            Ok(key) => key,
                            Err(e) => {
                                println!("❌ Failed to get master key: {}", e);
                                continue;
                            }
                        };
                        
                        // Get database reference for the importer
                        let db = vault.get_db_ref();
                        
                        match importer.import_credentials(
                            profile_path.clone(),
                            firefox_master_pass.as_deref(),
                            &db,
                            &master_key,
                            category,
                        ).await {
                            Ok(count) => {
                                println!("✅ Successfully imported {} passwords from Firefox!", count);
                            }
                            Err(e) => {
                                println!("❌ Failed to import passwords: {}", e);
                            }
                        }
                    }
                    "🌐  Import from Chrome" => {
                        // Create Chrome importer
                        let importer = crate::importers::ChromeImporter::new();
                        
                        // Find Chrome profiles
                        let profiles = importer.list_profiles();
                        
                        if profiles.is_empty() {
                            println!("❗ No Chrome profiles found.");
                            continue;
                        }
                        
                        // Display profiles for selection
                        let profile_display: Vec<String> = profiles
                            .iter()
                            .map(|(name, path)| format!("{} ({})", name, path.display()))
                            .collect();
                        
                        let selection = Select::new("Select Chrome profile:", profile_display.clone())
                            .with_page_size(50)
                            .prompt()?;
                        
                        // Find the selected profile
                        let selected_idx = profile_display.iter().position(|s| s == &selection).unwrap();
                        let (_, profile_path) = &profiles[selected_idx];
                        
                        // Choose category for imported passwords
                        let categories = get_categories(&vault, &token).await?;
                        let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                        
                        let category = if !category_names.is_empty() {
                            let selected = Select::new("Add imported passwords to category:", 
                                category_names.iter().chain(std::iter::once(&"[No Category]")).cloned().collect::<Vec<_>>())
                                .prompt()?;
                            
                            if selected == "[No Category]" {
                                None
                            } else {
                                Some(selected)
                            }
                        } else {
                            None
                        };
                        
                        // Import passwords
                        println!("Importing passwords from Chrome...");
                        
                        // Get the session ID and master key for importing
                        let session_id = match vault.auth_manager.validate_token(&token) {
                            Ok(sid) => sid,
                            Err(e) => {
                                println!("❌ Authentication error: {}", e);
                                continue;
                            }
                        };
                        
                        let master_key = match vault.auth_manager.get_master_key(&session_id) {
                            Ok(key) => key,
                            Err(e) => {
                                println!("❌ Failed to get master key: {}", e);
                                continue;
                            }
                        };
                        
                        // Get database reference for the importer
                        let db = vault.get_db_ref();
                        
                        match importer.import_passwords(
                            &db,
                            Some(&profile_path.to_string_lossy()),
                            &master_key,
                            category,
                        ).await {
                            Ok(count) => {
                                println!("✅ Successfully imported {} passwords from Chrome!", count);
                            },
                            Err(e) => {
                                println!("❌ Failed to import passwords: {}", e);
                            }
                        }
                    },
                    "🔷  Import from Edge" => {
                        // Create Edge importer
                        let importer = crate::importers::EdgeImporter::new();
                        
                        // Find Edge profiles
                        let profiles = importer.list_profiles();
                        
                        if profiles.is_empty() {
                            println!("❗ No Edge profiles found.");
                            continue;
                        }
                        
                        // Display profiles for selection
                        let profile_display: Vec<String> = profiles
                            .iter()
                            .map(|(name, path)| format!("{} ({})", name, path.display()))
                            .collect();
                        
                        let selection = Select::new("Select Edge profile:", profile_display.clone())
                            .with_page_size(50)
                            .prompt()?;
                        
                        // Find the selected profile
                        let selected_idx = profile_display.iter().position(|s| s == &selection).unwrap();
                        let (_, profile_path) = &profiles[selected_idx];
                        
                        // Choose category for imported passwords
                        let categories = get_categories(&vault, &token).await?;
                        let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                        
                        let category = if !category_names.is_empty() {
                            let selected = Select::new("Add imported passwords to category:", 
                                category_names.iter().chain(std::iter::once(&"[No Category]")).cloned().collect::<Vec<_>>())
                                .prompt()?;
                            
                            if selected == "[No Category]" {
                                None
                            } else {
                                Some(selected)
                            }
                        } else {
                            None
                        };
                        
                        // Import passwords
                        println!("Importing passwords from Edge...");
                        
                        // Get the session ID and master key for importing
                        let session_id = match vault.auth_manager.validate_token(&token) {
                            Ok(sid) => sid,
                            Err(e) => {
                                println!("❌ Authentication error: {}", e);
                                continue;
                            }
                        };
                        
                        let master_key = match vault.auth_manager.get_master_key(&session_id) {
                            Ok(key) => key,
                            Err(e) => {
                                println!("❌ Failed to get master key: {}", e);
                                continue;
                            }
                        };
                        
                        // Get database reference for the importer
                        let db = vault.get_db_ref();
                        
                        match importer.import_passwords(
                            &db,
                            Some(&profile_path.to_string_lossy()),
                            &master_key,
                            category,
                        ).await {
                            Ok(count) => {
                                println!("✅ Successfully imported {} passwords from Edge!", count);
                            },
                            Err(e) => {
                                println!("❌ Failed to import passwords: {}", e);
                            }
                        }
                    },
                    "📤  Import/Export CSV" => {
                        // CSV submenu
                        let csv_options = vec![
                            "Import from CSV",
                            "Export to CSV",
                            "Back to main menu",
                        ];
                        
                        let csv_selection = Select::new("Choose an option:", csv_options).prompt()?;
                        
                        match csv_selection {
                            "Import from CSV" => {
                                // Get CSV file path
                                let file_path = Text::new("Enter CSV file path:").prompt()?;
                                
                                // Check if file exists
                                if !std::path::Path::new(&file_path).exists() {
                                    println!("❌ File not found: {}", file_path);
                                    continue;
                                }
                                
                                // Get CSV options
                                let delimiter = Text::new("CSV delimiter (e.g. , or ;):")
                                    .with_default(",")
                                    .prompt()?;
                                
                                if delimiter.len() != 1 {
                                    println!("❌ Delimiter must be a single character");
                                    continue;
                                }
                                
                                let has_header = Confirm::new("Does the CSV have a header row?")
                                    .with_default(true)
                                    .prompt()?;
                                
                                // Choose category for imported passwords
                                let categories = get_categories(&vault, &token).await?;
                                let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                                
                                let category = if !category_names.is_empty() {
                                    let selected = Select::new("Add imported passwords to category:", 
                                        category_names.iter().chain(std::iter::once(&"[No Category]")).cloned().collect::<Vec<_>>())
                                        .prompt()?;
                                    
                                    if selected == "[No Category]" {
                                        None
                                    } else {
                                        Some(selected)
                                    }
                                } else {
                                    None
                                };
                                
                                // Import CSV
                                let importer = crate::importers::CsvImporter::new();
                                
                                println!("Importing passwords from CSV...");
                                
                                // Get the session ID and master key for importing
                                let session_id = match vault.auth_manager.validate_token(&token) {
                                    Ok(sid) => sid,
                                    Err(e) => {
                                        println!("❌ Authentication error: {}", e);
                                        continue;
                                    }
                                };
                                
                                let master_key = match vault.auth_manager.get_master_key(&session_id) {
                                    Ok(key) => key,
                                    Err(e) => {
                                        println!("❌ Failed to get master key: {}", e);
                                        continue;
                                    }
                                };
                                
                                // Get database reference for the importer
                                let db = vault.get_db_ref();
                                
                                match importer.import(
                                    std::path::Path::new(&file_path),
                                    &db,
                                    &master_key,
                                    delimiter.chars().next().unwrap(),
                                    has_header,
                                    category,
                                ).await {
                                    Ok(count) => {
                                        println!("✅ Successfully imported {} passwords from CSV!", count);
                                    }
                                    Err(e) => {
                                        println!("❌ Failed to import passwords: {}", e);
                                    }
                                }
                            }
                            "Export to CSV" => {
                                // Get CSV file path
                                let file_path = Text::new("Enter export CSV file path:").prompt()?;
                                
                                // Get CSV options
                                let delimiter = Text::new("CSV delimiter (e.g. , or ;):")
                                    .with_default(",")
                                    .prompt()?;
                                
                                if delimiter.len() != 1 {
                                    println!("❌ Delimiter must be a single character");
                                    continue;
                                }
                                
                                let include_header = Confirm::new("Include header row in CSV?")
                                    .with_default(true)
                                    .prompt()?;
                                
                                // Export to CSV
                                let exporter = crate::importers::CsvImporter::new();
                                
                                println!("Exporting passwords to CSV...");
                                
                                // Get the session ID and master key for exporting
                                let session_id = match vault.auth_manager.validate_token(&token) {
                                    Ok(sid) => sid,
                                    Err(e) => {
                                        println!("❌ Authentication error: {}", e);
                                        continue;
                                    }
                                };
                                
                                let master_key = match vault.auth_manager.get_master_key(&session_id) {
                                    Ok(key) => key,
                                    Err(e) => {
                                        println!("❌ Failed to get master key: {}", e);
                                        continue;
                                    }
                                };
                                
                                // Get database reference for the exporter
                                let db = vault.get_db_ref();
                                
                                match exporter.export(
                                    std::path::Path::new(&file_path),
                                    &db,
                                    &master_key,
                                    delimiter.chars().next().unwrap(),
                                    include_header,
                                ).await {
                                    Ok(count) => {
                                        println!("✅ Successfully exported {} passwords to CSV!", count);
                                    }
                                    Err(e) => {
                                        println!("❌ Failed to export passwords: {}", e);
                                    }
                                }
                            }
                            "Back to main menu" => {}
                            _ => {}
                        }
                    }
                    "🗂️  Manage categories" => {
                        // Categories submenu
                        let category_options = vec![
                            "List categories",
                            "Add category",
                            "Delete category",
                            "Back to main menu",
                        ];
                        
                        let category_selection = Select::new("Choose an option:", category_options).prompt()?;
                        
                        match category_selection {
                            "List categories" => {
                                let categories = get_categories(&vault, &token).await?;
                                
                                if categories.is_empty() {
                                    println!("❗ No categories defined yet.");
                                    continue;
                                }
                                
                                println!("\n📂 Categories:");
                                for (i, category) in categories.iter().enumerate() {
                                    println!("{}: {}", i + 1, category.name);
                                }
                                
                                // Wait for user to press enter
                                let _ = Text::new("Press enter to continue...").prompt();
                            }
                            "Add category" => {
                                let name = Text::new("Enter category name:").prompt()?;
                                
                                // Get database reference
                                let db = vault.get_db_ref();
                                
                                // Add the category
                                match db.get_or_create_category(&name).await {
                                    Ok(_) => println!("✅ Category '{}' added successfully!", name),
                                    Err(e) => println!("❌ Failed to add category: {}", e),
                                }
                            }
                            "Delete category" => {
                                let categories = get_categories(&vault, &token).await?;
                                
                                if categories.is_empty() {
                                    println!("❗ No categories defined yet.");
                                    continue;
                                }
                                
                                let category_names: Vec<&str> = categories.iter().map(|c| c.name.as_str()).collect();
                                
                                let selection = Select::new("Select category to delete:", category_names.clone()).prompt()?;
                                
                                // Find the selected category
                                let selected_idx = category_names.iter().position(|&s| s == selection).unwrap();
                                let selected = &categories[selected_idx];
                                
                                let confirm = Confirm::new(&format!("Are you sure you want to delete the category '{}'?", selected.name))
                                    .with_default(false)
                                    .prompt()?;
                                
                                if confirm {
                                    // Get database reference
                                    let db = vault.get_db_ref();
                                    
                                    match db.delete_category(selected.id).await {
                                        Ok(_) => println!("✅ Category deleted successfully!"),
                                        Err(e) => println!("❌ Failed to delete category: {}", e),
                                    }
                                }
                            }
                            "Back to main menu" => {}
                            _ => {}
                        }
                    }
                    "🔁  Change master password" => {
                        // Prompt once for current password
                        let current_password = Password::new("Enter current master password:")
                            .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                            .prompt();

                        if current_password.is_err() {
                            println!("❌ Failed to read current password.");
                            continue;
                        }

                        let current_password = current_password.unwrap();

                        // Try to unlock vault using current password
                        match vault.unlock(&current_password).await {
                            Ok(_) => {
                                // Prompt once for new password
                                let new_password = Password::new("Enter new master password:")
                                    .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                                    .prompt();

                                if new_password.is_err() {
                                    println!("❌ Failed to read new password.");
                                    continue;
                                }

                                let new_password = new_password.unwrap();

                                // Prompt once to confirm
                                let confirm_password = Password::new("Confirm new master password:")
                                    .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                                    .prompt();

                                if confirm_password.is_err() {
                                    println!("❌ Failed to read confirmation password.");
                                    continue;
                                }

                                let confirm_password = confirm_password.unwrap();

                                if new_password != confirm_password {
                                    println!("❌ Passwords do not match. Password not changed.");
                                    continue;
                                }

                                // Now update
                                match vault.update_master_password(&token, &current_password, &new_password).await {
                                    Ok(_) => println!("✅ Master password updated successfully!"),
                                    Err(e) => println!("❌ Failed to update master password: {}", e),
                                }
                            }
                            Err(_) => {
                                println!("❌ Invalid current password. Password not changed.");
                            }
                        }
                    }
                    "❌  Exit" => {
                        // First clean up any resources
                        println!("👋 Shutting down RustVault...");
                        
                        // Logout to clean up the session
                        if let Err(e) = vault.logout(&token) {
                            log::warn!("Failed to logout cleanly: {}", e);
                        }
                        
                        // Set the exit flag so the main thread knows to clean up
                        should_exit.store(true, Ordering::SeqCst);
                        
                        // Exit the menu loop
                        exit_requested = true;
                    }
                    _ => {}
                }
            }
            Ok(None) => {
                // Check if Ctrl+C was pressed
                if should_exit.load(Ordering::SeqCst) {
                    break;
                }
                // Sleep briefly to avoid consuming CPU while waiting for input
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
        }
    }

    // Log out to clean up the session
    if let Err(e) = vault.logout(&token) {
        log::warn!("Failed to logout cleanly: {}", e);
    }

    Ok(())
}

// Helper function to get categories
async fn get_categories(vault: &Vault, _token: &str) -> Result<Vec<Category>, Box<dyn Error>> {
    // Get database reference from vault
    let db = vault.get_db_ref();
    let categories = db.get_all_categories().await?;
    Ok(categories)
}