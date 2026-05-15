use super::{AdvancedTokenError, MIN_SALT_COUNT};

pub(super) fn validate_salts(values: Vec<String>) -> Result<Vec<String>, AdvancedTokenError> {
    let sanitized: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if sanitized.len() < MIN_SALT_COUNT {
        Err(AdvancedTokenError::Message(format!(
            "Salt array cannot be empty or less than {}.",
            MIN_SALT_COUNT
        )))
    } else {
        Ok(sanitized)
    }
}
