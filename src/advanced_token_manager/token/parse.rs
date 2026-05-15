use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::advanced_token_manager::native::{NativeTokenMeta, NativeTokenParts, TOKEN_VERSION};
use crate::advanced_token_manager::TokenValidationError;

pub(super) fn parse_token(token: &str) -> Result<NativeTokenParts, TokenValidationError> {
    let segments = split_token(token)?;
    let payload = decode_payload(segments.payload)?;
    let meta = decode_meta(segments.meta)?;
    Ok(NativeTokenParts {
        payload,
        meta,
        signing_input: format!("{}.{}.{}", TOKEN_VERSION, segments.payload, segments.meta),
        signature: segments.signature.to_string(),
    })
}

struct Segments<'a> {
    payload: &'a str,
    meta: &'a str,
    signature: &'a str,
}

fn split_token(token: &str) -> Result<Segments<'_>, TokenValidationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 || parts[0] != TOKEN_VERSION || parts.iter().any(|part| part.is_empty()) {
        return Err(TokenValidationError::new("Invalid native token structure."));
    }
    Ok(Segments {
        payload: parts[1],
        meta: parts[2],
        signature: parts[3],
    })
}

fn decode_payload(encoded: &str) -> Result<String, TokenValidationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TokenValidationError::new("Invalid native token payload."))?;
    String::from_utf8(bytes).map_err(|_| TokenValidationError::new("Payload is not valid UTF-8."))
}

fn decode_meta(encoded: &str) -> Result<NativeTokenMeta, TokenValidationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TokenValidationError::new("Invalid native token metadata."))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| TokenValidationError::new("Metadata is not valid JSON."))
}
