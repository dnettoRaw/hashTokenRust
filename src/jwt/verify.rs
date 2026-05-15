mod claims;
mod header;
mod payload;
mod temporal;

use super::signing::verify_signature;
use super::{JwtClaims, JwtError, VerifyJwtOptions};

pub(super) fn verify_token(token: &str, options: &VerifyJwtOptions) -> Result<JwtClaims, JwtError> {
    validate_verify_inputs(token, options)?;
    let segments = split_token(token)?;
    let algorithm = header::decode_algorithm(segments.header, options)?;
    let payload = payload::decode_payload(segments.payload, options)?;

    claims::enforce_allowed_claims(&payload, options)?;
    verify_signature(
        algorithm,
        &options.secret,
        segments.header,
        segments.payload,
        segments.signature,
    )?;
    claims::validate_registered_claims(&payload, options)?;
    Ok(payload)
}

pub(super) fn decode_json_object(bytes: &[u8], part: &str) -> Result<JwtClaims, JwtError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| JwtError::new(format!("JWT: invalid {} JSON.", part)))?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| JwtError::new(format!("JWT: {} must be a JSON object.", part)))
}

struct TokenSegments<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

fn validate_verify_inputs(token: &str, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if token.trim().is_empty() {
        return Err(JwtError::new("JWT: token must be a non-empty string."));
    }
    if options.secret.trim().is_empty() {
        return Err(JwtError::new(
            "JWT: a non-empty secret is required to verify.",
        ));
    }
    Ok(())
}

fn split_token(token: &str) -> Result<TokenSegments<'_>, JwtError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(JwtError::new("JWT: invalid token structure."));
    }
    Ok(TokenSegments {
        header: parts[0],
        payload: parts[1],
        signature: parts[2],
    })
}
