use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

use crate::base64url;
use crate::crypto;
use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::meta::Meta;
use crate::options::{ValidateTokenOptions, VerifiedBytes};
use crate::sealed::parts::{aad, split};
use crate::validate;

pub(crate) fn token(
    manager: &AdvancedTokenManager,
    token: &str,
    options: &ValidateTokenOptions<'_>,
) -> Result<VerifiedBytes, TokenError> {
    let parts = split(token)?;
    let meta = Meta::decode(parts.meta)?;
    validate::metadata(manager, &meta, options)?;
    let payload = open(
        manager,
        parts.ciphertext,
        parts.meta,
        parts.nonce,
        meta.salt_index,
    )?;
    Ok(VerifiedBytes::new(payload, meta))
}

fn open(
    manager: &AdvancedTokenManager,
    ciphertext: &str,
    meta: &str,
    nonce: &str,
    salt_index: usize,
) -> Result<Vec<u8>, TokenError> {
    let ciphertext = base64url::decode(ciphertext, "ciphertext")?;
    let nonce_bytes = decode_nonce(nonce)?;
    let key = crypto::sealing_key(
        manager.algorithm,
        &manager.secret,
        &manager.salts[salt_index],
    )?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: aad(meta, nonce).as_bytes(),
            },
        )
        .map_err(|_| TokenError::new("Failed to open sealed token."))
}

fn decode_nonce(encoded: &str) -> Result<[u8; 12], TokenError> {
    let nonce = base64url::decode(encoded, "nonce")?;
    nonce
        .try_into()
        .map_err(|_| TokenError::new("Invalid nonce length."))
}
