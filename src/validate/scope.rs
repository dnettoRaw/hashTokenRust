use crate::error::TokenError;
use crate::meta::Meta;
use crate::options::ValidateTokenOptions;

pub(crate) fn validate_scope(
    meta: &Meta,
    options: &ValidateTokenOptions<'_>,
) -> Result<(), TokenError> {
    match_required("issuer", meta.issuer.as_deref(), options.issuer)?;
    match_required("audience", meta.audience.as_deref(), options.audience)
}

fn match_required(
    name: &str,
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<(), TokenError> {
    match (actual, expected) {
        (_, None) => Ok(()),
        (Some(actual), Some(expected)) if actual == expected => Ok(()),
        (None, Some(_)) => Err(TokenError::new(format!("Missing {}.", name))),
        (Some(_), Some(_)) => Err(TokenError::new(format!("{} mismatch.", name))),
    }
}
