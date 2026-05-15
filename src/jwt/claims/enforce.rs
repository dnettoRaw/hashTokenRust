use serde_json::Value;

use crate::jwt::{JwtClaims, JwtError};

pub(super) fn enforce_claim(
    claims: &mut JwtClaims,
    key: &str,
    value: Value,
) -> Result<(), JwtError> {
    match claims.get(key) {
        Some(existing) if *existing != value => Err(JwtError::claim_conflict(key)),
        Some(_) => Ok(()),
        None => {
            claims.insert(key.to_string(), value);
            Ok(())
        }
    }
}
