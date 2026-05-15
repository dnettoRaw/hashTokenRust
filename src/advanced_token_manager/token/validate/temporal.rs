use crate::advanced_token_manager::native::NativeTokenMeta;
use crate::advanced_token_manager::time::{current_timestamp, positive_seconds};
use crate::advanced_token_manager::{TokenValidationError, ValidateTokenOptions};

pub(super) fn validate_temporal_metadata(
    meta: &NativeTokenMeta,
    options: &ValidateTokenOptions,
) -> Result<(), TokenValidationError> {
    let now = current_timestamp(options.clock_timestamp)?;
    let tolerance = normalize_tolerance(options.clock_tolerance)?;
    validate_expiration(meta, now, tolerance)?;
    validate_max_age(meta, options, now, tolerance)
}

fn normalize_tolerance(value: Option<f64>) -> Result<i64, TokenValidationError> {
    match value {
        Some(value) if value.is_finite() && value >= 0.0 => Ok(value.floor() as i64),
        Some(_) => Err(TokenValidationError::new(
            "clockTolerance must be a non-negative number.",
        )),
        None => Ok(0),
    }
}

fn validate_expiration(
    meta: &NativeTokenMeta,
    now: i64,
    tolerance: i64,
) -> Result<(), TokenValidationError> {
    if let Some(exp) = meta.exp {
        let exp = exp
            .checked_add(tolerance)
            .ok_or_else(|| TokenValidationError::new("Token temporal claim overflow."))?;
        if now > exp {
            return Err(TokenValidationError::new("Token expired."));
        }
    }
    Ok(())
}

fn validate_max_age(
    meta: &NativeTokenMeta,
    options: &ValidateTokenOptions,
    now: i64,
    tolerance: i64,
) -> Result<(), TokenValidationError> {
    if let Some(max_age) = options.max_age {
        let max_age = positive_seconds(max_age, "maxAge")?;
        let age = now
            .checked_sub(meta.iat)
            .and_then(|value| value.checked_sub(tolerance))
            .ok_or_else(|| TokenValidationError::new("Token temporal claim overflow."))?;
        if age > max_age {
            return Err(TokenValidationError::new("Token exceeds maxAge."));
        }
    }
    Ok(())
}
