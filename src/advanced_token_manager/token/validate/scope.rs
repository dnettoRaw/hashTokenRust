use crate::advanced_token_manager::native::NativeTokenMeta;
use crate::advanced_token_manager::{TokenValidationError, ValidateTokenOptions};

pub(super) fn verify_scope(
    meta: &NativeTokenMeta,
    options: &ValidateTokenOptions,
) -> Result<(), TokenValidationError> {
    require_match("issuer", meta.iss.as_deref(), options.issuer.as_deref())?;
    require_match("audience", meta.aud.as_deref(), options.audience.as_deref())
}

fn require_match(
    name: &str,
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<(), TokenValidationError> {
    match (actual, expected) {
        (_, None) => Ok(()),
        (Some(actual), Some(expected)) if actual == expected => Ok(()),
        (None, Some(_)) => Err(TokenValidationError::new(format!(
            "Missing required {}.",
            name
        ))),
        (Some(_), Some(_)) => Err(TokenValidationError::new(format!("{} mismatch.", name))),
    }
}
