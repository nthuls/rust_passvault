// src/api/handlers/tools.rs
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;
use crate::core::vault::Vault;
use crate::tools::dork::GoogleDorkBuilder;
use crate::api::types::{DorkRequest, DorkResponse};

#[utoipa::path(
    post,
    path = "/tools/dork",
    tag = "Tools",
    request_body(content = DorkRequest, description = "OSINT dork generation request"),
    responses(
        (status = 200, description = "Dork generated successfully"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    )
)]
pub async fn generate_dork(
    _vault: web::Data<Arc<Vault>>,
    req: web::Json<DorkRequest>,
) -> impl Responder {
    let dork_builder = GoogleDorkBuilder::new();
    
    // Convert date range if present
    let date_range = req.date_range.as_ref().map(|dr| {
        (dr.start_date.as_str(), dr.end_date.as_deref())
    });
    
    // Generate the dork query
    let result = dork_builder.generate_dork(
        &req.search_type,
        &req.keywords,
        req.exclude_terms.as_deref(),
        req.site_restrictions.as_deref(),
        req.file_types.as_deref(),
        date_range,
    );
    
    match result {
        Ok((dork_query, explanation)) => {
            HttpResponse::Ok().json(DorkResponse {
                success: true,
                dork_query: Some(dork_query),
                explanation: Some(explanation),
                error: None,
            })
        },
        Err(e) => {
            HttpResponse::BadRequest().json(DorkResponse {
                success: false,
                dork_query: None,
                explanation: None,
                error: Some(format!("Failed to generate dork: {}", e)),
            })
        }
    }
}