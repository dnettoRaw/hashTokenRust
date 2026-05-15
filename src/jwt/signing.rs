mod hmac;

use super::base64url;
use super::{JwtAlgorithm, JwtError};

pub(super) fn create_signature(
    algorithm: JwtAlgorithm,
    secret: &str,
    signing_input: &str,
) -> Result<String, JwtError> {
    let bytes = create_signature_buffer(algorithm, secret, signing_input)?;
    Ok(base64url::encode(bytes))
}

pub(super) fn verify_signature(
    algorithm: JwtAlgorithm,
    secret: &str,
    encoded_header: &str,
    encoded_payload: &str,
    encoded_signature: &str,
) -> Result<(), JwtError> {
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let provided_signature = base64url::decode(encoded_signature, "signature")?;
    let expected_signature = create_signature_buffer(algorithm, secret, &signing_input)?;
    constant_time_compare(&expected_signature, &provided_signature)
}

fn create_signature_buffer(
    algorithm: JwtAlgorithm,
    secret: &str,
    signing_input: &str,
) -> Result<Vec<u8>, JwtError> {
    match algorithm {
        JwtAlgorithm::HS256 => hmac::compute_hmac_sha256(secret, signing_input),
        JwtAlgorithm::HS512 => hmac::compute_hmac_sha512(secret, signing_input),
    }
}

fn constant_time_compare(expected: &[u8], provided: &[u8]) -> Result<(), JwtError> {
    if expected.len() != provided.len() {
        return Err(JwtError::new("JWT: invalid signature."));
    }

    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(provided) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Ok(())
    } else {
        Err(JwtError::new("JWT: invalid signature."))
    }
}
