mod scope;
mod temporal;

use crate::advanced_token_manager::crypto::constant_time_compare;
use crate::advanced_token_manager::native::{NativeTokenMeta, NativeTokenParts};
use crate::advanced_token_manager::{
    AdvancedTokenManager, TokenValidationError, ValidateTokenOptions,
};

pub(super) fn validate_metadata(
    meta: &NativeTokenMeta,
    options: &ValidateTokenOptions,
) -> Result<(), TokenValidationError> {
    if meta.v != 1 {
        return Err(TokenValidationError::new(
            "Unsupported native token version.",
        ));
    }
    temporal::validate_temporal_metadata(meta, options)
}

pub(super) fn verify_scope(
    meta: &NativeTokenMeta,
    options: &ValidateTokenOptions,
) -> Result<(), TokenValidationError> {
    scope::verify_scope(meta, options)
}

pub(super) fn verify_signature(
    manager: &AdvancedTokenManager,
    parts: &NativeTokenParts,
) -> Result<(), TokenValidationError> {
    let expected = manager.sign_native_input(&parts.signing_input, parts.meta.salt)?;
    if constant_time_compare(expected.as_bytes(), parts.signature.as_bytes()) {
        Ok(())
    } else {
        Err(TokenValidationError::new("Checksum mismatch."))
    }
}
