// src/api/middleware/auth.rs - Fixed for proper token handling

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::{ready, LocalBoxFuture, Ready};
use std::rc::Rc;
use std::task::{Context, Poll};
use crate::core::auth::AuthManager;
use log::{debug, warn, error};

// The TokenValidator struct that will be used to transform services
pub struct TokenValidator;

impl<S, B> Transform<S, ServiceRequest> for TokenValidator
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = TokenValidatorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(TokenValidatorMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct TokenValidatorMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for TokenValidatorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        // Handle OPTIONS requests immediately (for CORS preflight)
        if req.method() == actix_web::http::Method::OPTIONS {
            let fut = service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        // Process normal requests
        Box::pin(async move {
            // Extract token from authorization header
            let auth_header = req.headers().get("Authorization");
            
            let token = match auth_header {
                Some(header) => {
                    match header.to_str() {
                        Ok(header_str) => {
                            if header_str.starts_with("Bearer ") {
                                debug!("🔍 Found Bearer token in header");
                                header_str[7..].to_string()
                            } else {
                                warn!("❌ Invalid authorization header format: {}", header_str);
                                return Err(actix_web::error::ErrorUnauthorized("Invalid authorization header format"));
                            }
                        },
                        Err(_) => {
                            warn!("❌ Could not convert authorization header to string");
                            return Err(actix_web::error::ErrorUnauthorized("Invalid authorization header"));
                        }
                    }
                }
                None => {
                    warn!("❌ Missing authorization header");
                    return Err(actix_web::error::ErrorUnauthorized("Missing authorization header"));
                }
            };

            debug!("🔑 Token extracted: {}", token.chars().take(10).collect::<String>() + "...");
            
            // Create a new auth manager
            let auth_manager = AuthManager::new();
            
            // Validate token
            match auth_manager.validate_token(&token) {
                Ok(session_id) => {
                    debug!("✅ Token validation successful for session: {}", session_id);
                    
                    // Store both the token and session_id in request extensions
                    req.extensions_mut().insert(token.clone());
                    req.extensions_mut().insert(session_id.clone());
                    
                    // Add master key for convenience (avoids repeated lookups)
                    match auth_manager.get_master_key(&session_id) {
                        Ok(master_key) => {
                            debug!("✅ Master key retrieved successfully");
                            req.extensions_mut().insert(master_key);
                            
                            // Call the next service in the chain
                            let fut = service.call(req);
                            let res = fut.await?;
                            Ok(res)
                        },
                        Err(e) => {
                            error!("❌ Failed to get master key for session {}: {}", session_id, e);
                            Err(actix_web::error::ErrorUnauthorized("Session validation failed"))
                        }
                    }
                }
                Err(e) => {
                    warn!("❌ Token validation failed: {}", e);
                    Err(actix_web::error::ErrorUnauthorized(format!("Invalid or expired token: {}", e)))
                }
            }
        })
    }
}