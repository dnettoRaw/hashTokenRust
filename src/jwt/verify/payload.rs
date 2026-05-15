use super::decode_json_object;
use crate::jwt::base64url;
use crate::jwt::{JwtClaims, JwtError, VerifyJwtOptions};

pub(super) fn decode_payload(
    encoded_payload: &str,
    options: &VerifyJwtOptions,
) -> Result<JwtClaims, JwtError> {
    reject_large_payload_before_decode(encoded_payload, options)?;
    let payload_bytes = base64url::decode(encoded_payload, "payload")?;
    reject_large_payload_after_decode(payload_bytes.len(), options)?;
    decode_json_object(&payload_bytes, "payload")
}

fn reject_large_payload_before_decode(
    encoded_payload: &str,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    if options
        .max_payload_size
        .is_some_and(|max_size| base64url::decoded_len_upper_bound(encoded_payload) > max_size)
    {
        return Err(JwtError::new("JWT: payload exceeds maxPayloadSize."));
    }
    Ok(())
}

fn reject_large_payload_after_decode(
    payload_size: usize,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    if options
        .max_payload_size
        .is_some_and(|max_size| payload_size > max_size)
    {
        return Err(JwtError::new("JWT: payload exceeds maxPayloadSize."));
    }
    Ok(())
}
