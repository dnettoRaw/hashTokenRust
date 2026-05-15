mod max_age;

use crate::jwt::claims::numeric_claim;
use crate::jwt::time::current_timestamp;
use crate::jwt::{JwtClaims, JwtError, VerifyJwtOptions};

pub(super) fn validate_temporal_claims(
    payload: &JwtClaims,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    let now = current_timestamp(options.clock_timestamp)?;
    let tolerance = normalize_tolerance(options.clock_tolerance)?;
    validate_exp(payload, now, tolerance)?;
    validate_nbf(payload, now, tolerance)?;
    validate_iat(payload, now, tolerance)?;
    max_age::validate_max_age(payload, options, now, tolerance)
}

fn normalize_tolerance(clock_tolerance: Option<f64>) -> Result<i64, JwtError> {
    match clock_tolerance {
        Some(value) if value.is_finite() && value >= 0.0 => Ok(value.floor() as i64),
        Some(_) => Err(JwtError::new(
            "JWT: clockTolerance must be a non-negative number.",
        )),
        None => Ok(0),
    }
}

fn validate_exp(payload: &JwtClaims, now: i64, tolerance: i64) -> Result<(), JwtError> {
    if let Some(exp) = payload.get("exp") {
        let expires_with_tolerance = numeric_claim(exp, "exp")?
            .checked_add(tolerance)
            .ok_or_else(|| JwtError::new("JWT: temporal claim overflow."))?;
        if now > expires_with_tolerance {
            return Err(JwtError::new("JWT: token expired."));
        }
    }
    Ok(())
}

fn validate_nbf(payload: &JwtClaims, now: i64, tolerance: i64) -> Result<(), JwtError> {
    if let Some(nbf) = payload.get("nbf") {
        let now_with_tolerance = now
            .checked_add(tolerance)
            .ok_or_else(|| JwtError::new("JWT: temporal claim overflow."))?;
        if now_with_tolerance < numeric_claim(nbf, "nbf")? {
            return Err(JwtError::new("JWT: token not active yet."));
        }
    }
    Ok(())
}

fn validate_iat(payload: &JwtClaims, now: i64, tolerance: i64) -> Result<(), JwtError> {
    if let Some(iat) = payload.get("iat") {
        let issued_without_tolerance = numeric_claim(iat, "iat")?
            .checked_sub(tolerance)
            .ok_or_else(|| JwtError::new("JWT: temporal claim overflow."))?;
        if issued_without_tolerance > now {
            return Err(JwtError::new("JWT: token used before issued."));
        }
    }
    Ok(())
}
