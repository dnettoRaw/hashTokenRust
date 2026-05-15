use std::time::{SystemTime, UNIX_EPOCH};

use super::TokenValidationError;

pub(super) fn current_timestamp(clock: Option<f64>) -> Result<i64, TokenValidationError> {
    if let Some(value) = clock {
        if !value.is_finite() {
            return Err(TokenValidationError::new(
                "clockTimestamp must be a finite number.",
            ));
        }
        return Ok(value.floor() as i64);
    }

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenValidationError::new("System time before UNIX_EPOCH."))?;
    Ok(duration.as_secs() as i64)
}

pub(super) fn positive_seconds(value: f64, name: &str) -> Result<i64, TokenValidationError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(TokenValidationError::new(format!(
            "{} must be a positive number of seconds.",
            name
        )));
    }
    Ok(value.floor() as i64)
}
