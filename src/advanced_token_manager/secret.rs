use super::{AdvancedTokenError, MIN_SECRET_LENGTH};

pub(super) fn validate_secret(secret: String) -> Result<String, AdvancedTokenError> {
    if secret.len() < MIN_SECRET_LENGTH {
        Err(short_secret_error())
    } else {
        Ok(secret)
    }
}

pub(super) fn short_secret_error() -> AdvancedTokenError {
    AdvancedTokenError::Message(format!(
        "Secret must be at least {} characters long.",
        MIN_SECRET_LENGTH
    ))
}
