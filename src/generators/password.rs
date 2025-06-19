use crate::models::PasswordGenerationOptions;

pub struct PasswordGenerator;

impl PasswordGenerator {
    pub fn new() -> Self {
        PasswordGenerator
    }

    pub fn generate_password(&self, options: &PasswordGenerationOptions) -> Result<String, Box<dyn std::error::Error>> {
        Ok(crate::crypto::generate_password(options))
    }

    pub fn analyze_password_strength(&self, password: &str) -> u8 {
        crate::crypto::analyze_password_strength(password)
    }
}
