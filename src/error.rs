//! Error type returned by token generation, validation, sealing, and opening.
use std::error::Error;
use std::fmt::{self, Display};

/// Small owned error with a human-readable validation or crypto failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenError {
    message: String,
}

impl TokenError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for TokenError {}
