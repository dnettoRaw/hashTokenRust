use serde_json::Value;

use super::enforce::enforce_claim;
use super::validate::ensure_string;
use crate::jwt::{JwtClaims, JwtError};

pub(crate) fn normalize_string(value: String, context: &str) -> Result<String, JwtError> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(JwtError::new(format!(
            "JWT: {} must be a non-empty string.",
            context
        )));
    }
    Ok(trimmed)
}

pub(crate) fn apply_issuer(claims: &mut JwtClaims, issuer: Option<String>) -> Result<(), JwtError> {
    apply_string_claim(claims, "iss", issuer, "Issuer")
}

pub(crate) fn apply_subject(
    claims: &mut JwtClaims,
    subject: Option<String>,
) -> Result<(), JwtError> {
    apply_string_claim(claims, "sub", subject, "Subject")
}

fn apply_string_claim(
    claims: &mut JwtClaims,
    key: &str,
    value: Option<String>,
    context: &str,
) -> Result<(), JwtError> {
    if let Some(value) = value {
        enforce_claim(
            claims,
            key,
            Value::String(normalize_string(value, context)?),
        )
    } else if let Some(existing) = claims.get(key) {
        ensure_string(existing, key)
    } else {
        Ok(())
    }
}
