use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::jwt::JwtError;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub(super) fn compute_hmac_sha256(secret: &str, signing_input: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| JwtError::new("JWT: failed to create HMAC instance."))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn compute_hmac_sha512(secret: &str, signing_input: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .map_err(|_| JwtError::new("JWT: failed to create HMAC instance."))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}
