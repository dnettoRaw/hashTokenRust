mod allowed;

use crate::jwt::claims::{string_claim, validate_audience_value};
use crate::jwt::verify::temporal::validate_temporal_claims;
use crate::jwt::{JwtClaims, JwtError, VerifyJwtOptions};

const STANDARD_CLAIMS: [&str; 6] = ["iss", "sub", "aud", "exp", "nbf", "iat"];

pub(super) fn enforce_allowed_claims(
    payload: &JwtClaims,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    if let Some(allowed_claims) = &options.allowed_claims {
        let allowed = allowed::normalize_allowed_claims(allowed_claims)?;
        for key in payload.keys() {
            if !STANDARD_CLAIMS.contains(&key.as_str()) && !allowed.contains(key) {
                return Err(JwtError::new(format!(
                    "JWT: claim \"{}\" is not allowed.",
                    key
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn validate_registered_claims(
    payload: &JwtClaims,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    validate_temporal_claims(payload, options)?;
    validate_audience(payload, options)?;
    validate_issuer(payload, options)?;
    validate_subject(payload, options)
}

fn validate_audience(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("aud").is_none() && options.audience.is_none() {
        return Ok(());
    }

    let token_audience = payload
        .get("aud")
        .ok_or_else(|| JwtError::new("JWT: missing required audience claim."))
        .and_then(validate_audience_value)?;
    if let Some(audience) = options.audience.clone() {
        let expected = audience.into_vec()?;
        if !expected
            .iter()
            .any(|value| token_audience.iter().any(|aud| aud == value))
        {
            return Err(JwtError::new("JWT: audience mismatch."));
        }
    }
    Ok(())
}

fn validate_issuer(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("iss").is_none() && options.issuer.is_none() {
        return Ok(());
    }

    let issuer = payload
        .get("iss")
        .ok_or_else(|| JwtError::new("JWT: missing required issuer claim."))
        .and_then(|value| string_claim(value, "iss"))?;
    if let Some(issuer_option) = options.issuer.clone() {
        let allowed = issuer_option.into_vec()?;
        if !allowed.contains(&issuer) {
            return Err(JwtError::new("JWT: issuer mismatch."));
        }
    }
    Ok(())
}

fn validate_subject(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("sub").is_none() && options.subject.is_none() {
        return Ok(());
    }

    let subject = payload
        .get("sub")
        .ok_or_else(|| JwtError::new("JWT: missing required subject claim."))
        .and_then(|value| string_claim(value, "sub"))?;
    if options
        .subject
        .as_ref()
        .is_some_and(|expected| subject != expected.trim())
    {
        return Err(JwtError::new("JWT: subject mismatch."));
    }
    Ok(())
}
