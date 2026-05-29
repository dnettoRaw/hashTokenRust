use crate::base64url;
use crate::crypto;
use crate::error::TokenError;

pub(crate) fn signature(expected: &[u8], encoded: &str) -> Result<(), TokenError> {
    let provided = base64url::decode(encoded, "signature")?;
    if crypto::constant_time_eq(expected, &provided) {
        Ok(())
    } else {
        Err(TokenError::new("Invalid token signature."))
    }
}
