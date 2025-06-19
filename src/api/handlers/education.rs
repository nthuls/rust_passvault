// src/api/handlers/education.rs
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;
use crate::core::vault::Vault;
use crate::education::EducationManager;
use crate::api::types::{TopicListResponse, TopicContentResponse};

#[utoipa::path(
    get,
    path = "/education",
    tag = "Education",
    responses(
        (status = 200, description = "List of available education topics", body = TopicListResponse),
        (status = 500, description = "Server error", body = TopicListResponse)
    )
)]
pub async fn list_topics(
    _vault: web::Data<Arc<Vault>>,
) -> impl Responder {
    let education_manager = EducationManager::new();
    let topics = education_manager.get_all_topics();
    
    HttpResponse::Ok().json(TopicListResponse {
        success: true,
        topics,
        error: None,
    })
}
#[utoipa::path(
    get,
    path = "/education/{id}",
    tag = "Education",
    params(
        ("id" = String, Path, description = "Topic ID to retrieve")
    ),
    responses(
        (status = 200, description = "Topic content", body = TopicContentResponse),
        (status = 404, description = "Topic not found", body = TopicContentResponse),
        (status = 500, description = "Server error", body = TopicContentResponse)
    )
)]
pub async fn get_topic(
    _vault: web::Data<Arc<Vault>>,
    path: web::Path<String>,
) -> impl Responder {
    let topic_id = path.into_inner();
    let education_manager = EducationManager::new();
    
    match education_manager.get_topic_by_id(&topic_id) {
        Some(topic) => {
            HttpResponse::Ok().json(TopicContentResponse {
                success: true,
                topic: Some(topic),
                error: None,
            })
        },
        None => {
            HttpResponse::NotFound().json(TopicContentResponse {
                success: false,
                topic: None,
                error: Some(format!("Topic not found: {}", topic_id)),
            })
        }
    }
}