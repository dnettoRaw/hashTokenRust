//! Public signed-token API.
//!
//! Signed tokens use the `htr1.payload.metadata.signature` shape. The payload is
//! readable Base64URL, while metadata and payload are protected by HMAC.
pub(crate) mod build;
mod parts;

use crate::base64url;
use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::options::{GenerateTokenOptions, ValidateTokenOptions, VerifiedBytes, VerifiedToken};
use crate::validate;

pub(crate) const VERSION: &str = "htr1";

impl AdvancedTokenManager {
    /// Generates a signed token from a UTF-8 payload.
    pub fn generate_token(
        &mut self,
        payload: &str,
        options: GenerateTokenOptions<'_>,
    ) -> Result<String, TokenError> {
        self.generate_token_bytes(payload.as_bytes(), options)
    }

    /// Generates a signed token from raw bytes.
    pub fn generate_token_bytes(
        &mut self,
        payload: &[u8],
        options: GenerateTokenOptions<'_>,
    ) -> Result<String, TokenError> {
        build::token(self, payload, &options)
    }

    /// Validates a signed token and returns a UTF-8 payload.
    pub fn validate_token(
        &self,
        token: &str,
        options: ValidateTokenOptions<'_>,
    ) -> Result<VerifiedToken, TokenError> {
        let verified = self.validate_token_bytes(token, options)?;
        let VerifiedBytes {
            payload,
            issued_at,
            expires_at,
            issuer,
            audience,
            salt_index,
            algorithm,
        } = verified;
        let payload =
            String::from_utf8(payload).map_err(|_| TokenError::new("Payload is not UTF-8."))?;
        Ok(VerifiedToken {
            payload,
            issued_at,
            expires_at,
            issuer,
            audience,
            salt_index,
            algorithm,
        })
    }

    /// Validates a signed token and returns only the UTF-8 payload.
    pub fn validate_payload(
        &self,
        token: &str,
        options: ValidateTokenOptions<'_>,
    ) -> Result<String, TokenError> {
        self.validate_token(token, options)
            .map(|verified| verified.payload)
    }

    /// Validates a signed token and returns raw payload bytes.
    pub fn validate_token_bytes(
        &self,
        token: &str,
        options: ValidateTokenOptions<'_>,
    ) -> Result<VerifiedBytes, TokenError> {
        let parts = parts::split(token)?;
        let payload = base64url::decode(parts.payload, "payload")?;
        let meta = crate::meta::Meta::decode(parts.meta)?;
        validate::metadata(self, &meta, &options)?;
        let expected = self.sign(
            parts::signing_input(parts.payload, parts.meta).as_bytes(),
            meta.salt_index,
        )?;
        validate::signature(&expected, parts.signature)?;
        Ok(VerifiedBytes::new(payload, meta))
    }
}
