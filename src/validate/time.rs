//! Time validation for expiration and maximum age.
//!
//! Callers may inject `clock_timestamp` for tests or for binaries that centralize
//! time. Clock tolerance is only a small allowance around configured limits.
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::TokenError;
use crate::meta::Meta;
use crate::options::ValidateTokenOptions;

pub(crate) fn now() -> Result<u64, TokenError> {
    // Retorna Result para nao esconder sistemas com relogio antes do UNIX_EPOCH.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| TokenError::new("System time is before UNIX_EPOCH."))
}

pub(crate) fn validate_time(
    meta: &Meta,
    options: &ValidateTokenOptions<'_>,
) -> Result<(), TokenError> {
    // clock_timestamp deixa teste deterministico e tambem ajuda binarios que ja
    // recebem o tempo de uma camada externa confiavel.
    let now = match options.clock_timestamp {
        Some(value) => value,
        None => now()?,
    };
    let tolerance = options.clock_tolerance.unwrap_or(0);
    validate_expiration(meta, now, tolerance)?;
    validate_max_age(meta, now, tolerance, options.max_age)
}

fn validate_expiration(meta: &Meta, now: u64, tolerance: u64) -> Result<(), TokenError> {
    // Tolerancia amplia o exp para compensar drift pequeno, mas overflow continua
    // sendo erro porque seria impossivel saber a janela real.
    if let Some(exp) = meta.expires_at {
        let exp = exp
            .checked_add(tolerance)
            .ok_or_else(|| TokenError::new("Token expiration overflow."))?;
        if now > exp {
            return Err(TokenError::new("Token expired."));
        }
    }
    Ok(())
}

fn validate_max_age(
    meta: &Meta,
    now: u64,
    tolerance: u64,
    max_age: Option<u64>,
) -> Result<(), TokenError> {
    // max_age limita vida util mesmo quando o token nao tem exp gravado.
    if let Some(max_age) = max_age {
        let age = now
            .checked_sub(meta.issued_at)
            .and_then(|value| value.checked_sub(tolerance))
            .ok_or_else(|| TokenError::new("Token timestamp is outside valid range."))?;
        if age > max_age {
            return Err(TokenError::new("Token exceeds maxAge."));
        }
    }
    Ok(())
}
