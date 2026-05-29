//! Minimal native tokens for standalone Rust programs.
//!
//! `hash_token_rust` signs or seals small pieces of data using a shared
//! secret, one or more salts, and explicit validation options. Signed tokens
//! keep the payload readable and protected by HMAC. Sealed tokens encrypt the
//! payload and authenticate the metadata.
//!
//! The crate is intentionally small: the public entry point is
//! [`AdvancedTokenManager`], options are plain structs, and failures return
//! [`TokenError`] instead of panicking.
mod base64url;
mod crypto;
mod error;
mod manager;
mod meta;
mod options;
mod sealed;
mod token;
mod validate;

pub use error::TokenError;
pub use manager::{AdvancedTokenManager, Algorithm};
pub use options::{GenerateTokenOptions, ValidateTokenOptions, VerifiedBytes, VerifiedToken};

/// Current library version exposed for binaries that want to log or compare it.
pub const LIBRARY_VERSION: &str = "0.3.5";
