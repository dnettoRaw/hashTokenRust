use serde_json::Value;

use crate::jwt::{JwtClaims, JwtError, VerifyJwtOptions};

pub(super) fn validate_max_age(
    payload: &JwtClaims,
    options: &VerifyJwtOptions,
    now: i64,
    tolerance: i64,
) -> Result<(), JwtError> {
    if let Some(max_age) = options.max_age {
        let max_age = normalize_max_age(max_age)?;
        let iat = payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| JwtError::new("JWT: cannot apply maxAge without an \"iat\" claim."))?;
        let age = now
            .checked_sub(iat)
            .and_then(|value| value.checked_sub(tolerance))
            .ok_or_else(|| JwtError::new("JWT: temporal claim overflow."))?;
        if age > max_age {
            return Err(JwtError::new("JWT: token exceeds maxAge."));
        }
    }
    Ok(())
}

fn normalize_max_age(max_age: f64) -> Result<i64, JwtError> {
    if !max_age.is_finite() || max_age <= 0.0 {
        return Err(JwtError::new(
            "JWT: maxAge must be a positive number of seconds.",
        ));
    }
    Ok(max_age.floor() as i64)
}
