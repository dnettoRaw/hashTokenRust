use super::AdvancedTokenError;
use crate::jwt::JwtAlgorithm;

pub(super) fn normalize_positive_usize(
    name: &str,
    value: Option<usize>,
) -> Result<Option<usize>, AdvancedTokenError> {
    match value {
        None => Ok(None),
        Some(0) => Err(AdvancedTokenError::Message(format!(
            "{} must be a positive number.",
            name
        ))),
        Some(value) => Ok(Some(value)),
    }
}

pub(super) fn normalize_allowed_claims(
    allowed: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, AdvancedTokenError> {
    match allowed {
        None => Ok(None),
        Some(values) => normalize_unique_strings(values, "jwtAllowedClaims"),
    }
}

pub(super) fn normalize_algorithms(
    algorithms: Option<Vec<JwtAlgorithm>>,
) -> Result<Option<Vec<JwtAlgorithm>>, AdvancedTokenError> {
    match algorithms {
        None => Ok(None),
        Some(values) if values.is_empty() => Err(AdvancedTokenError::Message(
            "jwtDefaultAlgorithms must be a non-empty array when provided.".to_string(),
        )),
        Some(values) => Ok(Some(unique_algorithms(values))),
    }
}

fn normalize_unique_strings(
    values: Vec<String>,
    name: &str,
) -> Result<Option<Vec<String>>, AdvancedTokenError> {
    let mut unique = Vec::new();
    for value in values {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            return Err(AdvancedTokenError::Message(format!(
                "{} must be an array of non-empty strings.",
                name
            )));
        }
        if !unique.contains(&trimmed) {
            unique.push(trimmed);
        }
    }
    Ok(Some(unique))
}

fn unique_algorithms(values: Vec<JwtAlgorithm>) -> Vec<JwtAlgorithm> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}
