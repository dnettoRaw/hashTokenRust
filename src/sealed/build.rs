use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;

use crate::base64url;
use crate::crypto;
use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::meta::Meta;
use crate::options::GenerateTokenOptions;
use crate::sealed::parts::aad;
use crate::sealed::VERSION;

pub(crate) fn token(
    manager: &mut AdvancedTokenManager,
    payload: &[u8],
    options: &GenerateTokenOptions<'_>,
) -> Result<String, TokenError> {
    let salt_index = manager.select_salt(options.salt_index)?;
    let meta = meta(manager, salt_index, options)?;
    let encoded_meta = meta.encode()?;
    let nonce = nonce();
    let encoded_nonce = base64url::encode(&nonce);
    let ciphertext = seal(
        manager,
        salt_index,
        payload,
        &encoded_meta,
        &encoded_nonce,
        &nonce,
    )?;
    assemble(
        &base64url::encode(&ciphertext),
        &encoded_meta,
        &encoded_nonce,
    )
}

fn meta(
    manager: &AdvancedTokenManager,
    salt_index: usize,
    options: &GenerateTokenOptions<'_>,
) -> Result<Meta, TokenError> {
    let issued_at = options.issued_at.map_or_else(crate::validate::now, Ok)?;
    Ok(Meta {
        algorithm: manager.algorithm.name().to_string(),
        salt_index,
        issued_at,
        expires_at: crate::token::build::expiration(issued_at, options.expires_in)?,
        issuer: options.issuer.map(str::to_string),
        audience: options.audience.map(str::to_string),
    })
}

fn seal(
    manager: &AdvancedTokenManager,
    salt_index: usize,
    payload: &[u8],
    meta: &str,
    encoded_nonce: &str,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, TokenError> {
    let key = crypto::sealing_key(
        manager.algorithm,
        &manager.secret,
        &manager.salts[salt_index],
    )?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: payload,
                aad: aad(meta, encoded_nonce).as_bytes(),
            },
        )
        .map_err(|_| TokenError::new("Failed to seal token."))
}

fn nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

fn assemble(ciphertext: &str, meta: &str, nonce: &str) -> Result<String, TokenError> {
    let mut token =
        String::with_capacity(VERSION.len() + ciphertext.len() + meta.len() + nonce.len() + 3);
    token.push_str(VERSION);
    token.push('.');
    token.push_str(ciphertext);
    token.push('.');
    token.push_str(meta);
    token.push('.');
    token.push_str(nonce);
    Ok(token)
}
