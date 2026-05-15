use std::str::FromStr;

use serde_json::Value;

use super::decode_json_object;
use crate::jwt::base64url;
use crate::jwt::{JwtAlgorithm, JwtClaims, JwtError, VerifyJwtOptions};

pub(super) fn decode_algorithm(
    encoded_header: &str,
    options: &VerifyJwtOptions,
) -> Result<JwtAlgorithm, JwtError> {
    let header_bytes = base64url::decode(encoded_header, "header")?;
    let header = decode_json_object(&header_bytes, "header")?;
    validate_header_type(&header)?;
    let algorithm = parse_algorithm(&header)?;
    enforce_allowed_algorithm(algorithm, options)?;
    Ok(algorithm)
}

fn parse_algorithm(header: &JwtClaims) -> Result<JwtAlgorithm, JwtError> {
    let alg_value = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| JwtError::new("JWT: missing algorithm."))?;
    if alg_value.eq_ignore_ascii_case("none") {
        return Err(JwtError::new(
            "JWT: unsigned tokens (alg \"none\") are not allowed.",
        ));
    }
    JwtAlgorithm::from_str(alg_value)
}

fn validate_header_type(header: &JwtClaims) -> Result<(), JwtError> {
    if let Some(typ_value) = header.get("typ") {
        let typ = typ_value
            .as_str()
            .ok_or_else(|| JwtError::new("JWT: header type must be a string."))?;
        if typ != "JWT" {
            return Err(JwtError::new("JWT: header type must be \"JWT\"."));
        }
    }
    Ok(())
}

fn enforce_allowed_algorithm(
    algorithm: JwtAlgorithm,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    if options
        .algorithms
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&algorithm))
    {
        return Err(JwtError::new(format!(
            "JWT: algorithm {} is not allowed.",
            algorithm
        )));
    }
    Ok(())
}
