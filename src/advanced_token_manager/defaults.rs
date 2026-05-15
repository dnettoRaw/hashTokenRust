use super::AdvancedTokenError;

pub(super) fn resolve_length_option(
    name: &str,
    provided: Option<usize>,
    fallback: usize,
    minimum: usize,
) -> Result<usize, AdvancedTokenError> {
    match provided {
        None => Ok(fallback),
        Some(value) if value < minimum => Err(AdvancedTokenError::Message(format!(
            "{} must be an integer greater than or equal to {}.",
            name, minimum
        ))),
        Some(value) => Ok(value),
    }
}
