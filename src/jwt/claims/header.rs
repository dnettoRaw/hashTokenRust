use serde_json::Value;

use crate::jwt::{JwtAlgorithm, JwtClaims, JwtError, SignJwtOptions};

pub(crate) fn build_header(
    options: &SignJwtOptions,
    algorithm: JwtAlgorithm,
) -> Result<JwtClaims, JwtError> {
    let mut header = options.header.clone().unwrap_or_default();
    validate_header_override(&header, algorithm)?;
    header.insert("alg".to_string(), Value::String(algorithm.to_string()));
    header.insert("typ".to_string(), Value::String("JWT".to_string()));
    Ok(header)
}

fn validate_header_override(header: &JwtClaims, algorithm: JwtAlgorithm) -> Result<(), JwtError> {
    if header
        .get("alg")
        .is_some_and(|alg| alg.as_str() != Some(&algorithm.to_string()))
    {
        return Err(JwtError::new("JWT: header algorithm mismatch."));
    }
    if header
        .get("typ")
        .is_some_and(|typ| typ.as_str() != Some("JWT"))
    {
        return Err(JwtError::new("JWT: header type must be \"JWT\"."));
    }
    Ok(())
}
