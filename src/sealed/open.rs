//! Sealed-token opening and authenticated decryption.
//!
//! Validation runs before decryption so unknown salts, wrong algorithms, and
//! expired metadata are rejected without touching the payload.
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
    // Primeiro desmonta e valida metadata. A chave depende do salt index, entao
    // ele precisa ser confiavel antes de tentar abrir o payload.
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
    // Ciphertext e nonce continuam em Base64URL no token para manter o formato
    // seguro para trafegar em texto, env var, URL e logs controlados.
    let ciphertext = base64url::decode(ciphertext, "ciphertext")?;
    let nonce_bytes = decode_nonce(nonce)?;
    let key = crypto::sealing_key(
        manager.algorithm,
        &manager.secret,
        &manager.salts[salt_index],
    )?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    // O mesmo AAD usado ao selar precisa bater aqui. Se metadata ou nonce mudar,
    // a autenticacao falha antes de devolver qualquer byte.
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
    // ChaCha20-Poly1305 usa nonce de 96 bits. Qualquer outro tamanho e formato
    // invalido, mesmo se o Base64URL estiver bem formado.
    nonce
        .try_into()
        .map_err(|_| TokenError::new("Invalid nonce length."))
}
