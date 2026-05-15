use serde::de::DeserializeOwned;

use super::{
    AdvancedTokenError, AdvancedTokenManager, ManagerSignJwtOptions, ManagerVerifyJwtOptions,
};
use crate::jwt::{sign_jwt, verify_jwt_as, JwtClaims, SignJwtOptions, VerifyJwtOptions};

impl AdvancedTokenManager {
    pub fn generate_jwt(
        &self,
        payload: &JwtClaims,
        options: Option<ManagerSignJwtOptions>,
    ) -> Result<String, AdvancedTokenError> {
        let options = options.unwrap_or_default();
        let sign_options = SignJwtOptions {
            secret: options.secret.unwrap_or_else(|| self.secret.clone()),
            algorithm: options.algorithm,
            header: options.header,
            expires_in: options.expires_in,
            not_before: options.not_before,
            audience: options.audience,
            issuer: options.issuer,
            subject: options.subject,
            issued_at: options.issued_at,
            clock_timestamp: options.clock_timestamp,
        };
        Ok(sign_jwt(payload, &sign_options)?)
    }

    pub fn validate_jwt<T: DeserializeOwned>(
        &self,
        token: &str,
        options: Option<ManagerVerifyJwtOptions>,
    ) -> Result<T, AdvancedTokenError> {
        let options = options.unwrap_or_default();
        let verify_options = VerifyJwtOptions {
            secret: options.secret.unwrap_or_else(|| self.secret.clone()),
            algorithms: options
                .algorithms
                .or_else(|| self.jwt_default_algorithms.clone()),
            clock_tolerance: options.clock_tolerance,
            audience: options.audience,
            issuer: options.issuer,
            subject: options.subject,
            max_age: options.max_age,
            clock_timestamp: options.clock_timestamp,
            max_payload_size: options.max_payload_size.or(self.jwt_max_payload_size),
            allowed_claims: options
                .allowed_claims
                .or_else(|| self.jwt_allowed_claims.clone()),
        };
        Ok(verify_jwt_as(token, &verify_options)?)
    }
}
