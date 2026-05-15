use thiserror::Error;

use crate::jwt::JwtError;

#[derive(Debug, Error)]
pub enum AdvancedTokenError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

#[derive(Debug, Error, Clone)]
pub enum TokenValidationError {
    #[error("{0}")]
    Message(String),
}

impl TokenValidationError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}
