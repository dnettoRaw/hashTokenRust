mod base64url;
mod claims;
mod error;
mod signing;
mod time;
mod types;
mod verify;

use serde::de::DeserializeOwned;
use serde_json::Value;

pub use error::JwtError;
pub use types::{Audience, Issuer, JwtAlgorithm, JwtClaims, SignJwtOptions, VerifyJwtOptions};

use claims::{
    apply_audience, apply_expires_in, apply_issued_at, apply_issuer, apply_not_before,
    apply_subject,
};
use signing::create_signature;
use time::current_timestamp;
use verify::verify_token;

pub fn sign_jwt(payload: &JwtClaims, options: &SignJwtOptions) -> Result<String, JwtError> {
    if options.secret.trim().is_empty() {
        return Err(JwtError::new(
            "JWT: a non-empty secret is required to sign.",
        ));
    }

    let algorithm = options.algorithm.unwrap_or(JwtAlgorithm::HS256);
    let header = claims::build_header(options, algorithm)?;
    let timestamp = current_timestamp(options.clock_timestamp)?;
    let mut claims = payload.clone();

    apply_issued_at(&mut claims, options.issued_at, timestamp)?;
    apply_expires_in(&mut claims, options.expires_in, timestamp)?;
    apply_not_before(&mut claims, options.not_before, timestamp)?;
    apply_audience(&mut claims, options.audience.clone())?;
    apply_issuer(&mut claims, options.issuer.clone())?;
    apply_subject(&mut claims, options.subject.clone())?;

    let encoded_header = encode_json_object(&header, "header")?;
    let encoded_payload = encode_json_object(&claims, "payload")?;
    let signing_input = format!("{}.{}", &encoded_header, &encoded_payload);
    let signature = create_signature(algorithm, &options.secret, &signing_input)?;

    Ok(format!(
        "{}.{}.{}",
        encoded_header, encoded_payload, signature
    ))
}

pub fn verify_jwt(token: &str, options: &VerifyJwtOptions) -> Result<JwtClaims, JwtError> {
    verify_token(token, options)
}

pub fn verify_jwt_as<T: DeserializeOwned>(
    token: &str,
    options: &VerifyJwtOptions,
) -> Result<T, JwtError> {
    let claims = verify_jwt(token, options)?;
    serde_json::from_value(Value::Object(claims))
        .map_err(|_| JwtError::new("JWT: payload could not be deserialized into target type."))
}

fn encode_json_object(claims: &JwtClaims, part: &str) -> Result<String, JwtError> {
    let json = serde_json::to_vec(&Value::Object(claims.clone()))
        .map_err(|_| JwtError::new(format!("JWT: failed to serialize {}.", part)))?;
    Ok(base64url::encode(json))
}
