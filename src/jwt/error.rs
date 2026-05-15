use thiserror::Error;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct JwtError {
    message: String,
}

impl JwtError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(super) fn claim_conflict(claim: &str) -> Self {
        Self::new(format!(
            "JWT: claim \"{}\" already present with a different value.",
            claim
        ))
    }
}
