//! Cryptographic primitives used by the token formats.
//!
//! Signed mode uses HMAC. Sealed mode derives a 32-byte AEAD key from the same
//! secret and selected salt using domain-separated HMAC input.
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
    // Mantemos a escolha do algoritmo aqui para o resto do codigo nao conhecer
    // detalhes de HMAC/SHA.
    match algorithm {
        Algorithm::Sha256 => hmac_sha256(secret, salt, input),
        Algorithm::Sha512 => hmac_sha512(secret, salt, input),
    }
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // Keep comparison work independent from byte contents once lengths match.
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

pub(crate) fn sealing_key(
    algorithm: Algorithm,
    secret: &[u8],
    salt: &[u8],
) -> Result<[u8; 32], TokenError> {
    // String fixa separa o uso "sealed" do uso "signed"; mesmo segredo e salt
    // nao geram material equivalente para finalidades diferentes.
    let digest = sign(algorithm, secret, salt, b"hash-token-rust:sealed:v1")?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    Ok(key)
}

fn hmac_sha256(secret: &[u8], salt: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenError> {
    // O salt entra depois do input para manter signing_input legivel e estavel.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| TokenError::new("Invalid HMAC key."))?;
    mac.update(input);
    mac.update(salt);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(secret: &[u8], salt: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenError> {
    // Mesma regra do SHA-256, apenas com digest maior.
    let mut mac =
        Hmac::<Sha512>::new_from_slice(secret).map_err(|_| TokenError::new("Invalid HMAC key."))?;
    mac.update(input);
    mac.update(salt);
    Ok(mac.finalize().into_bytes().to_vec())
}
