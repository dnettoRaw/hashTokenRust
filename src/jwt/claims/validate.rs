use serde_json::Value;

use crate::jwt::JwtError;

pub(crate) fn numeric_claim(value: &Value, claim: &str) -> Result<i64, JwtError> {
    ensure_numeric(value, claim)?;
    value
        .as_i64()
        .ok_or_else(|| JwtError::new(format!("JWT: Claim \"{}\" must be a finite number.", claim)))
}

pub(crate) fn string_claim(value: &Value, claim: &str) -> Result<String, JwtError> {
    ensure_string(value, claim)?;
    value.as_str().map(ToString::to_string).ok_or_else(|| {
        JwtError::new(format!(
            "JWT: Claim \"{}\" must be a non-empty string.",
            claim
        ))
    })
}

pub(crate) fn ensure_numeric(value: &Value, claim: &str) -> Result<(), JwtError> {
    match value {
        Value::Number(number) if number.as_i64().is_some() => Ok(()),
        _ => Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a finite number.",
            claim
        ))),
    }
}

pub(crate) fn ensure_string(value: &Value, claim: &str) -> Result<(), JwtError> {
    match value {
        Value::String(text) if !text.is_empty() => Ok(()),
        _ => Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a non-empty string.",
            claim
        ))),
    }
}
