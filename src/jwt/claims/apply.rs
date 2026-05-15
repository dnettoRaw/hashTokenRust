use serde_json::Value;

use super::audience::audience_value;
use super::enforce::enforce_claim;
use super::validate::ensure_numeric;
use crate::jwt::time::normalize_number;
use crate::jwt::{Audience, JwtClaims, JwtError};

pub(crate) fn apply_issued_at(
    claims: &mut JwtClaims,
    issued_at: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = issued_at {
        enforce_claim(claims, "iat", Value::from(normalize_number(value, "iat")?))
    } else if let Some(existing) = claims.get("iat") {
        ensure_numeric(existing, "iat")
    } else {
        claims.insert("iat".to_string(), Value::from(timestamp));
        Ok(())
    }
}

pub(crate) fn apply_expires_in(
    claims: &mut JwtClaims,
    expires_in: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = expires_in {
        let exp = checked_duration_claim(value, timestamp, "expiresIn")?;
        enforce_claim(claims, "exp", Value::from(exp))
    } else if let Some(existing) = claims.get("exp") {
        ensure_numeric(existing, "exp")
    } else {
        Ok(())
    }
}

pub(crate) fn apply_not_before(
    claims: &mut JwtClaims,
    not_before: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = not_before {
        if !value.is_finite() {
            return Err(JwtError::new("JWT: notBefore must be a number of seconds."));
        }
        enforce_claim(claims, "nbf", Value::from(timestamp + value.floor() as i64))
    } else if let Some(existing) = claims.get("nbf") {
        ensure_numeric(existing, "nbf")
    } else {
        Ok(())
    }
}

pub(crate) fn apply_audience(
    claims: &mut JwtClaims,
    audience: Option<Audience>,
) -> Result<(), JwtError> {
    if let Some(audience) = audience {
        let audiences = audience.into_vec()?;
        enforce_claim(claims, "aud", audience_value(audiences))
    } else if let Some(existing) = claims.get("aud") {
        super::audience::validate_audience_value(existing).map(|_| ())
    } else {
        Ok(())
    }
}

fn checked_duration_claim(value: f64, timestamp: i64, name: &str) -> Result<i64, JwtError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(JwtError::new(format!(
            "JWT: {} must be a positive number of seconds.",
            name
        )));
    }
    timestamp
        .checked_add(value.floor() as i64)
        .ok_or_else(|| JwtError::new("JWT: temporal claim overflow."))
}
