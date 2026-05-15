use std::collections::HashSet;

use crate::jwt::JwtError;

pub(super) fn normalize_allowed_claims(
    allowed_claims: &[String],
) -> Result<HashSet<String>, JwtError> {
    let mut normalized = HashSet::new();
    for claim in allowed_claims {
        let trimmed = claim.trim();
        if trimmed.is_empty() {
            return Err(JwtError::new(
                "JWT: allowedClaims must be an array of non-empty strings.",
            ));
        }
        normalized.insert(trimmed.to_string());
    }
    Ok(normalized)
}
