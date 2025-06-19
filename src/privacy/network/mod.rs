// src/privacy/network/mod.rs
use serde::{Serialize, Deserialize};
use utoipa::ToSchema;

pub mod dns;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct NetworkSettings {
    pub dns_privacy: bool,
    pub referer_control: bool,
    pub user_agent_management: bool,
    pub tls_fingerprinting_mitigation: bool,
}

impl NetworkSettings {
    // Check if any network protection is active
    pub fn is_active(&self) -> bool {
        self.dns_privacy || 
        self.referer_control || 
        self.user_agent_management || 
        self.tls_fingerprinting_mitigation
    }
}