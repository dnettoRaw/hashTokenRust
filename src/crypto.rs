use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::error::TokenError;
use crate::manager::Algorithm;

pub(crate) fn sign(
    algorithm: Algorithm,
    secret: &[u8],
    salt: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, TokenError> {
    match algorithm {
        Algorithm::Sha256 => hmac_sha256(secret, salt, input),
        Algorithm::Sha512 => hmac_sha512(secret, salt, input),
    }
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn hmac_sha256(secret: &[u8], salt: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| TokenError::new("Invalid HMAC key."))?;
    mac.update(input);
    mac.update(salt);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(secret: &[u8], salt: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenError> {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(secret).map_err(|_| TokenError::new("Invalid HMAC key."))?;
    mac.update(input);
    mac.update(salt);
    Ok(mac.finalize().into_bytes().to_vec())
}
