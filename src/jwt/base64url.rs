use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::JwtError;

const BASE64URL_ALLOWED: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(super) fn encode<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub(super) fn decode(input: &str, part: &str) -> Result<Vec<u8>, JwtError> {
    if !input.bytes().all(|byte| BASE64URL_ALLOWED.contains(&byte)) {
        return Err(JwtError::new(format!(
            "JWT: invalid base64url encoding in {}.",
            part
        )));
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| JwtError::new(format!("JWT: malformed base64url segment in {}.", part)))?;
    reject_non_canonical(input, &decoded, part)?;
    Ok(decoded)
}

pub(super) fn decoded_len_upper_bound(input: &str) -> usize {
    input.len().saturating_mul(3).saturating_add(3) / 4
}

fn reject_non_canonical(input: &str, decoded: &[u8], part: &str) -> Result<(), JwtError> {
    if encode(decoded) == input.trim_end_matches('=') {
        Ok(())
    } else {
        Err(JwtError::new(format!(
            "JWT: malformed base64url segment in {}.",
            part
        )))
    }
}
