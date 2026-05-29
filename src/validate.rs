//! Shared validation pipeline for signed and sealed tokens.
//!
//! Validation is deliberately ordered: salt index, algorithm, time, and scope
//! are checked before signature verification or decryption uses metadata.
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
    // Ordem importante: primeiro garante que a metadata aponta para algo que este
    // manager entende, depois aplica regras de tempo e escopo.
    manager.validate_salt_index(meta.salt_index)?;
    validate_algorithm(manager, meta)?;
    time::validate_time(meta, options)?;
    scope::validate_scope(meta, options)
}

fn validate_algorithm(manager: &AdvancedTokenManager, meta: &Meta) -> Result<(), TokenError> {
    // Nao existe downgrade automatico: o algoritmo do token precisa ser o mesmo
    // configurado no manager atual.
    if meta.algorithm == manager.algorithm.name() {
        Ok(())
    } else {
        Err(TokenError::new("Algorithm mismatch."))
    }
}
