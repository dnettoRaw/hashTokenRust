use std::time::{SystemTime, UNIX_EPOCH};

use super::JwtError;

pub(super) fn current_timestamp(clock: Option<f64>) -> Result<i64, JwtError> {
    if let Some(value) = clock {
        if !value.is_finite() {
            return Err(JwtError::new(
                "JWT: clockTimestamp must be a finite number.",
            ));
        }
        return Ok(value.floor() as i64);
    }

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JwtError::new("JWT: system time before UNIX_EPOCH."))?;
    Ok(duration.as_secs() as i64)
}

pub(super) fn normalize_number(value: f64, claim: &str) -> Result<i64, JwtError> {
    if !value.is_finite() {
        return Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a finite number.",
            claim
        )));
    }
    Ok(value.floor() as i64)
}
