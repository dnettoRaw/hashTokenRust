mod build;
mod open;
mod parts;

use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::options::{GenerateTokenOptions, ValidateTokenOptions, VerifiedBytes, VerifiedToken};

pub(crate) const VERSION: &str = "hte1";

impl AdvancedTokenManager {
    pub fn seal_token(
        &mut self,
        payload: &str,
        options: GenerateTokenOptions<'_>,
    ) -> Result<String, TokenError> {
        self.seal_token_bytes(payload.as_bytes(), options)
    }

    pub fn seal_token_bytes(
        &mut self,
        payload: &[u8],
        options: GenerateTokenOptions<'_>,
    ) -> Result<String, TokenError> {
        build::token(self, payload, &options)
    }

    pub fn open_token(
        &self,
        token: &str,
        options: ValidateTokenOptions<'_>,
    ) -> Result<VerifiedToken, TokenError> {
        let verified = self.open_token_bytes(token, options)?;
        let payload = String::from_utf8(verified.payload)
            .map_err(|_| TokenError::new("Payload is not UTF-8."))?;
        Ok(VerifiedToken {
            payload,
            issued_at: verified.issued_at,
            expires_at: verified.expires_at,
            issuer: verified.issuer,
            audience: verified.audience,
            salt_index: verified.salt_index,
            algorithm: verified.algorithm,
        })
    }

    pub fn open_token_bytes(
        &self,
        token: &str,
        options: ValidateTokenOptions<'_>,
    ) -> Result<VerifiedBytes, TokenError> {
        open::token(self, token, &options)
    }
}
