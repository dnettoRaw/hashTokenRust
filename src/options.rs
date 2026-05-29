#[derive(Clone, Debug, Default)]
pub struct GenerateTokenOptions<'a> {
    pub salt_index: Option<usize>,
    pub expires_in: Option<u64>,
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub issued_at: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct ValidateTokenOptions<'a> {
    pub max_age: Option<u64>,
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub clock_tolerance: Option<u64>,
    pub clock_timestamp: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    pub payload: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub salt_index: usize,
    pub algorithm: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBytes {
    pub payload: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub salt_index: usize,
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
