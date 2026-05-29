use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::TokenError;

pub(crate) fn encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn decode(input: &str, name: &str) -> Result<Vec<u8>, TokenError> {
    if input.is_empty() || !input.bytes().all(is_allowed) {
        return Err(TokenError::new(format!("Invalid {} encoding.", name)));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| TokenError::new(format!("Malformed {} encoding.", name)))?;
    if encode(&decoded) != input {
        return Err(TokenError::new(format!("Non-canonical {} encoding.", name)));
    }
    Ok(decoded)
}

fn is_allowed(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}
