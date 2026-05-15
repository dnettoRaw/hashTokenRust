use serde_json::Value;

use super::validate::string_claim;
use crate::jwt::JwtError;

pub(super) fn audience_value(audiences: Vec<String>) -> Value {
    if audiences.len() == 1 {
        Value::String(audiences[0].clone())
    } else {
        Value::Array(audiences.into_iter().map(Value::String).collect())
    }
}

pub(crate) fn validate_audience_value(value: &Value) -> Result<Vec<String>, JwtError> {
    if value.is_array() {
        normalize_audience_array(value)
    } else {
        Ok(vec![string_claim(value, "aud")?])
    }
}

fn normalize_audience_array(value: &Value) -> Result<Vec<String>, JwtError> {
    let items = value
        .as_array()
        .ok_or_else(|| JwtError::new("JWT: audience must be an array of strings."))?;
    if items.is_empty() {
        return Err(JwtError::new("JWT: audience array must not be empty."));
    }

    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        normalized.push(string_claim(item, "aud")?);
    }
    Ok(normalized)
}
