use std::sync::Arc;

use serde_json::{Map, Value};

use crate::advanced_token_manager::AdvancedTokenManagerLogger;
use crate::jwt::{Audience, Issuer, JwtAlgorithm};

#[derive(Default, Clone)]
pub struct AdvancedTokenManagerOptions {
    pub logger: Option<Arc<dyn AdvancedTokenManagerLogger>>,
    pub jwt_default_algorithms: Option<Vec<JwtAlgorithm>>,
    pub default_secret_length: Option<usize>,
    pub default_salt_count: Option<usize>,
    pub default_salt_length: Option<usize>,
    pub throw_on_validation_failure: Option<bool>,
    pub jwt_max_payload_size: Option<usize>,
    pub jwt_allowed_claims: Option<Vec<String>>,
}

#[derive(Default, Clone)]
pub struct GenerateTokenOptions {
    pub salt_index: Option<usize>,
    pub expires_in: Option<f64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub issued_at: Option<f64>,
}

#[derive(Default, Clone)]
pub struct ValidateTokenOptions {
    pub throw_on_failure: Option<bool>,
    pub max_age: Option<f64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub clock_tolerance: Option<f64>,
    pub clock_timestamp: Option<f64>,
}

#[derive(Default, Clone)]
pub struct ManagerSignJwtOptions {
    pub secret: Option<String>,
    pub algorithm: Option<JwtAlgorithm>,
    pub header: Option<Map<String, Value>>,
    pub expires_in: Option<f64>,
    pub not_before: Option<f64>,
    pub audience: Option<Audience>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub issued_at: Option<f64>,
    pub clock_timestamp: Option<f64>,
}

#[derive(Default, Clone)]
pub struct ManagerVerifyJwtOptions {
    pub secret: Option<String>,
    pub algorithms: Option<Vec<JwtAlgorithm>>,
    pub clock_tolerance: Option<f64>,
    pub audience: Option<Audience>,
    pub issuer: Option<Issuer>,
    pub subject: Option<String>,
    pub max_age: Option<f64>,
    pub clock_timestamp: Option<f64>,
    pub max_payload_size: Option<usize>,
    pub allowed_claims: Option<Vec<String>>,
}
