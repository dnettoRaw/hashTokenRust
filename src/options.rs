//! Public option and verification result types.
//!
//! Options are structs instead of long argument lists so callers can set only
//! the validation rules that matter for each token flow.

/// Controls how a signed or sealed token is created.
#[derive(Clone, Debug, Default)]
pub struct GenerateTokenOptions<'a> {
    /// Salt index to use. When omitted, the manager selects one randomly.
    pub salt_index: Option<usize>,
    /// Relative expiration in seconds, added to `issued_at`.
    pub expires_in: Option<u64>,
    /// Optional issuer value stored in metadata.
    pub issuer: Option<&'a str>,
    /// Optional audience value stored in metadata.
    pub audience: Option<&'a str>,
    /// Fixed issued-at timestamp for deterministic tests or external clocks.
    pub issued_at: Option<u64>,
}

/// Controls how a signed or sealed token is validated.
#[derive(Clone, Debug, Default)]
pub struct ValidateTokenOptions<'a> {
    /// Maximum token age in seconds, measured from `issued_at`.
    pub max_age: Option<u64>,
    /// Required issuer. Validation fails when metadata is missing or different.
    pub issuer: Option<&'a str>,
    /// Required audience. Validation fails when metadata is missing or different.
    pub audience: Option<&'a str>,
    /// Seconds allowed around expiration and max-age checks.
    pub clock_tolerance: Option<u64>,
    /// Fixed current timestamp for deterministic tests or external clocks.
    pub clock_timestamp: Option<u64>,
}

/// Verified UTF-8 payload plus the metadata that was authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    /// Original UTF-8 payload.
    pub payload: String,
    /// Token creation timestamp.
    pub issued_at: u64,
    /// Optional absolute expiration timestamp.
    pub expires_at: Option<u64>,
    /// Optional issuer from metadata.
    pub issuer: Option<String>,
    /// Optional audience from metadata.
    pub audience: Option<String>,
    /// Salt index used to sign or seal the token.
    pub salt_index: usize,
    /// Algorithm name stored in metadata, such as `HS256`.
    pub algorithm: String,
}

/// Verified binary payload plus the metadata that was authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBytes {
    /// Original payload bytes.
    pub payload: Vec<u8>,
    /// Token creation timestamp.
    pub issued_at: u64,
    /// Optional absolute expiration timestamp.
    pub expires_at: Option<u64>,
    /// Optional issuer from metadata.
    pub issuer: Option<String>,
    /// Optional audience from metadata.
    pub audience: Option<String>,
    /// Salt index used to sign or seal the token.
    pub salt_index: usize,
    /// Algorithm name stored in metadata, such as `HS512`.
    pub algorithm: String,
}

impl VerifiedBytes {
    pub(crate) fn new(payload: Vec<u8>, meta: crate::meta::Meta) -> Self {
        Self {
            payload,
            issued_at: meta.issued_at,
            expires_at: meta.expires_at,
            issuer: meta.issuer,
            audience: meta.audience,
            salt_index: meta.salt_index,
            algorithm: meta.algorithm,
        }
    }
}
