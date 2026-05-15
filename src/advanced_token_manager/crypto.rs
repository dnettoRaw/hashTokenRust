use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use super::{Algorithm, TokenValidationError};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

impl Algorithm {
    pub(super) fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "HS256",
            Algorithm::Sha512 => "HS512",
        }
    }

    pub(super) fn to_hmac(
        self,
        secret: &[u8],
        input: &[u8],
    ) -> Result<Vec<u8>, TokenValidationError> {
        match self {
            Algorithm::Sha256 => compute_hmac_sha256(secret, input),
            Algorithm::Sha512 => compute_hmac_sha512(secret, input),
        }
    }
}

fn compute_hmac_sha256(secret: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenValidationError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| TokenValidationError::new("Invalid HMAC key."))?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_hmac_sha512(secret: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenValidationError> {
    let mut mac = HmacSha512::new_from_slice(secret)
        .map_err(|_| TokenValidationError::new("Invalid HMAC key."))?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn constant_time_compare(expected: &[u8], provided: &[u8]) -> bool {
    if expected.len() != provided.len() {
        return false;
    }

    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(provided) {
        diff |= a ^ b;
    }
    diff == 0
}
