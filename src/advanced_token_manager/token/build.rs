use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::advanced_token_manager::native::{NativeTokenMeta, TOKEN_VERSION};
use crate::advanced_token_manager::time::positive_seconds;
use crate::advanced_token_manager::TokenValidationError;

pub(super) fn build_token(
    payload: &str,
    meta: &NativeTokenMeta,
    signature: &str,
) -> Result<String, TokenValidationError> {
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let encoded_meta = encode_meta(meta)?;
    Ok(format!(
        "{}.{}.{}.{}",
        TOKEN_VERSION, encoded_payload, encoded_meta, signature
    ))
}

pub(super) fn signing_input(
    payload: &str,
    meta: &NativeTokenMeta,
) -> Result<String, TokenValidationError> {
    let encoded_payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let encoded_meta = encode_meta(meta)?;
    Ok(format!(
        "{}.{}.{}",
        TOKEN_VERSION, encoded_payload, encoded_meta
    ))
}

pub(super) fn expiration(
    issued_at: i64,
    expires_in: Option<f64>,
) -> Result<Option<i64>, TokenValidationError> {
    match expires_in {
        Some(value) => Ok(Some(
            issued_at
                .checked_add(positive_seconds(value, "expiresIn")?)
                .ok_or_else(|| TokenValidationError::new("Token temporal claim overflow."))?,
        )),
        None => Ok(None),
    }
}

fn encode_meta(meta: &NativeTokenMeta) -> Result<String, TokenValidationError> {
    let json = serde_json::to_vec(meta)
        .map_err(|_| TokenValidationError::new("Failed to serialize token metadata."))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}
