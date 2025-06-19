// src/api/handlers/categories.rs

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use std::sync::Arc;
use uuid::Uuid;
use crate::core::vault::Vault;
use crate::api::types::{
    CategoryListResponse, CategoryEntry, 
    AddCategoryRequest, UpdateCategoryRequest, SuccessResponse
};
use crate::api::utils::extract_token;
use log::{info, error};
use utoipa::ToSchema;

/// List all categories
///
/// Returns a list of all categories in the vault.
#[utoipa::path(
    get,
    path = "/categories",
    tag = "Categories",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "List of categories", body = CategoryListResponse),
        (status = 401, description = "Unauthorized", body = CategoryListResponse)
    )
)]
pub async fn list_categories(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
) -> impl Responder {
    // Extract token
    let (token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(CategoryListResponse {
                success: false,
                categories: vec![],
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Get all categories
    match db.get_all_categories().await {
        Ok(categories) => {
            // Convert to API format
            let category_entries: Vec<CategoryEntry> = categories
                .into_iter()
                .map(|c| CategoryEntry {
                    id: c.id.to_string(),
                    name: c.name,
                })
                .collect();
            
            HttpResponse::Ok().json(CategoryListResponse {
                success: true,
                categories: category_entries,
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to get categories: {}", e);
            HttpResponse::InternalServerError().json(CategoryListResponse {
                success: false,
                categories: vec![],
                error: Some(format!("Failed to get categories: {}", e)),
            })
        }
    }
}

/// Add a new category
///
/// Creates a new category in the vault.
#[utoipa::path(
    post,
    path = "/categories",
    tag = "Categories",
    security(
        ("bearer_auth" = [])
    ),
    request_body = AddCategoryRequest,
    responses(
        (status = 200, description = "Category added", body = SuccessResponse),
        (status = 400, description = "Invalid input", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse)
    )
)]
pub async fn add_category(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    category_req: web::Json<AddCategoryRequest>,
) -> impl Responder {
    // Extract token
    let (token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Validate category name
    if category_req.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Category name cannot be empty".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Create the category
    match db.get_or_create_category(&category_req.name).await {
        Ok(category_id) => {
            info!("Category '{}' created with ID: {}", category_req.name, category_id);
            HttpResponse::Created().json(SuccessResponse {
                success: true,
                message: Some(format!("Category '{}' created successfully", category_req.name)),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to create category: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to create category: {}", e)),
            })
        }
    }
}

/// Update a category
///
/// Updates an existing category in the vault.
#[utoipa::path(
    put,
    path = "/categories/{id}",
    tag = "Categories",
    params(
        ("id" = String, Path, description = "Category ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    request_body = AddCategoryRequest,
    responses(
        (status = 200, description = "Category updated", body = SuccessResponse),
        (status = 400, description = "Invalid input", body = SuccessResponse),
        (status = 404, description = "Category not found", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse)
    )
)]
pub async fn update_category(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    path: web::Path<String>,
    category_req: web::Json<UpdateCategoryRequest>,
) -> impl Responder {
    // Extract token
    let (token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Parse UUID
    let id = match Uuid::parse_str(&path) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Invalid UUID format".to_string()),
            });
        }
    };
    
    // Validate category name
    if category_req.name.trim().is_empty() {
        return HttpResponse::BadRequest().json(SuccessResponse {
            success: false,
            message: None,
            error: Some("Category name cannot be empty".to_string()),
        });
    }
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // First check if the category exists
    let existing_categories = match db.get_all_categories().await {
        Ok(categories) => categories,
        Err(e) => {
            error!("Failed to get categories: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to get categories: {}", e)),
            });
        }
    };
    
    // Find the category by ID
    let category = existing_categories.iter().find(|c| c.id == id);
    
    if category.is_none() {
        return HttpResponse::NotFound().json(SuccessResponse {
            success: false,
            message: None,
            error: Some(format!("Category with ID {} not found", id)),
        });
    }
    
    // Now we need to implement the update functionality
    // Since your DB module might not have a direct update_category function,
    // we'll implement a workaround:
    
    // 1. Create a new category with the new name
    let new_category_id = match db.get_or_create_category(&category_req.name).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to create new category: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to update category: {}", e)),
            });
        }
    };
    
    // 2. Update all passwords to use the new category instead of the old one
    let passwords = match db.get_all_passwords().await {
        Ok(passwords) => passwords,
        Err(e) => {
            error!("Failed to get passwords: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to update category references: {}", e)),
            });
        }
    };
    
    // Start a transaction for the update
    let mut tx = match db.begin_transaction().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to start transaction: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Database error: {}", e)),
            });
        }
    };
    
    let old_category_name = category.unwrap().name.clone();
    
    // Update passwords that use the old category
    for password in passwords {
        if password.categories.contains(&old_category_name) {
            // Replace old category with new one
            let mut new_categories = password.categories.clone();
            if let Some(pos) = new_categories.iter().position(|c| c == &old_category_name) {
                new_categories[pos] = category_req.name.clone();
            }
            
            // Update the password with new categories
            match db.update_password_in_transaction(
                &mut tx,
                password.id,
                None,
                None,
                None,
                None,
                Some(&new_categories),
            ).await {
                Ok(_) => {},
                Err(e) => {
                    // Rollback on error
                    let _ = db.rollback_transaction(tx).await;
                    error!("Failed to update password categories: {}", e);
                    return HttpResponse::InternalServerError().json(SuccessResponse {
                        success: false,
                        message: None,
                        error: Some(format!("Failed to update category references: {}", e)),
                    });
                }
            }
        }
    }
    
    // 3. Delete the old category
    match db.delete_category(id).await {
        Ok(_) => {},
        Err(e) => {
            // Rollback on error
            let _ = db.rollback_transaction(tx).await;
            error!("Failed to delete old category: {}", e);
            return HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to delete old category: {}", e)),
            });
        }
    }
    
    // Commit the transaction
    match db.commit_transaction(tx).await {
        Ok(_) => {
            info!("Category '{}' updated to '{}'", old_category_name, category_req.name);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some(format!("Category updated successfully")),
                error: None,
            })
        },
        Err(e) => {
            error!("Failed to commit transaction: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to update category: {}", e)),
            })
        }
    }
}

/// Delete a category
///
/// Deletes a category from the vault.
#[utoipa::path(
    delete,
    path = "/categories/{id}",
    tag = "Categories",
    params(
        ("id" = String, Path, description = "Category ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Category deleted", body = SuccessResponse),
        (status = 404, description = "Category not found", body = SuccessResponse),
        (status = 401, description = "Unauthorized", body = SuccessResponse)
    )
)]
pub async fn delete_category(
    vault: web::Data<Arc<Vault>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    // Extract token
    let (token, _) = match extract_token(&req) {
        Ok(result) => result,
        Err(e) => {
            return HttpResponse::Unauthorized().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Authentication error: {}", e)),
            });
        }
    };
    
    // Parse UUID
    let id = match Uuid::parse_str(&path) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(SuccessResponse {
                success: false,
                message: None,
                error: Some("Invalid UUID format".to_string()),
            });
        }
    };
    
    // Get database reference
    let db = vault.get_db_ref();
    
    // Delete the category
    match db.delete_category(id).await {
        Ok(_) => {
            info!("Category with ID {} deleted", id);
            HttpResponse::Ok().json(SuccessResponse {
                success: true,
                message: Some("Category deleted successfully".to_string()),
                error: None,
            })
        },
        Err(e) => {
            // Handle "not found" error specifically
            if format!("{}", e).contains("not found") {
                return HttpResponse::NotFound().json(SuccessResponse {
                    success: false,
                    message: None,
                    error: Some(format!("Category with ID {} not found", id)),
                });
            }
            
            error!("Failed to delete category: {}", e);
            HttpResponse::InternalServerError().json(SuccessResponse {
                success: false,
                message: None,
                error: Some(format!("Failed to delete category: {}", e)),
            })
        }
    }
}