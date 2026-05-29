mod scope;
mod signature;
mod time;

use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::meta::Meta;
use crate::options::ValidateTokenOptions;

pub(crate) use signature::signature;
pub(crate) use time::now;

pub(crate) fn metadata(
    manager: &AdvancedTokenManager,
    meta: &Meta,
    options: &ValidateTokenOptions<'_>,
) -> Result<(), TokenError> {
    manager.validate_salt_index(meta.salt_index)?;
    validate_algorithm(manager, meta)?;
    time::validate_time(meta, options)?;
    scope::validate_scope(meta, options)
}

fn validate_algorithm(manager: &AdvancedTokenManager, meta: &Meta) -> Result<(), TokenError> {
    if meta.algorithm == manager.algorithm.name() {
        Ok(())
    } else {
        Err(TokenError::new("Algorithm mismatch."))
    }
}
