use super::defaults::resolve_length_option;
use super::env::{resolve_salt_candidates, resolve_secret_candidate};
use super::normalize::{normalize_algorithms, normalize_allowed_claims, normalize_positive_usize};
use super::random::generate_random_key;
use super::salts::validate_salts;
use super::secret::{short_secret_error, validate_secret};
use super::{
    AdvancedTokenError, AdvancedTokenManagerLogger, AdvancedTokenManagerOptions,
    DEFAULT_SALT_COUNT, DEFAULT_SALT_LENGTH, DEFAULT_SECRET_LENGTH, MIN_SALT_COUNT,
    MIN_SECRET_LENGTH,
};
use crate::jwt::JwtAlgorithm;

pub(super) struct ManagerDefaults {
    pub secret_length: usize,
    pub salt_count: usize,
    pub salt_length: usize,
}

pub(super) struct JwtManagerOptions {
    pub default_algorithms: Option<Vec<JwtAlgorithm>>,
    pub throw_on_validation_failure: bool,
    pub max_payload_size: Option<usize>,
    pub allowed_claims: Option<Vec<String>>,
}

pub(super) fn resolve_defaults(
    options: &AdvancedTokenManagerOptions,
) -> Result<ManagerDefaults, AdvancedTokenError> {
    Ok(ManagerDefaults {
        secret_length: resolve_length_option(
            "defaultSecretLength",
            options.default_secret_length,
            DEFAULT_SECRET_LENGTH,
            MIN_SECRET_LENGTH,
        )?,
        salt_count: resolve_length_option(
            "defaultSaltCount",
            options.default_salt_count,
            DEFAULT_SALT_COUNT,
            MIN_SALT_COUNT,
        )?,
        salt_length: resolve_length_option(
            "defaultSaltLength",
            options.default_salt_length,
            DEFAULT_SALT_LENGTH,
            1,
        )?,
    })
}

pub(super) fn resolve_jwt_options(
    options: AdvancedTokenManagerOptions,
) -> Result<JwtManagerOptions, AdvancedTokenError> {
    Ok(JwtManagerOptions {
        default_algorithms: normalize_algorithms(options.jwt_default_algorithms)?,
        throw_on_validation_failure: options.throw_on_validation_failure.unwrap_or(false),
        max_payload_size: normalize_positive_usize(
            "jwtMaxPayloadSize",
            options.jwt_max_payload_size,
        )?,
        allowed_claims: normalize_allowed_claims(options.jwt_allowed_claims)?,
    })
}

pub(super) fn initialize_secret(
    secret: Option<String>,
    allow_auto_generate: bool,
    no_env: bool,
    default_length: usize,
    logger: &dyn AdvancedTokenManagerLogger,
) -> Result<String, AdvancedTokenError> {
    let candidate = resolve_secret_candidate(secret, no_env);
    match candidate {
        Some(secret) => validate_secret(secret),
        None if allow_auto_generate => {
            let generated = generate_random_key(default_length);
            logger.warn("⚠️ Secret generated automatically. Store it securely.");
            Ok(generated)
        }
        None => Err(short_secret_error()),
    }
}

pub(super) fn initialize_salts(
    salts: Option<Vec<String>>,
    allow_auto_generate: bool,
    no_env: bool,
    default_count: usize,
    default_length: usize,
    logger: &dyn AdvancedTokenManagerLogger,
) -> Result<Vec<String>, AdvancedTokenError> {
    match resolve_salt_candidates(salts, no_env) {
        Some(values) => validate_salts(values),
        None if allow_auto_generate => {
            let salts = (0..default_count)
                .map(|_| generate_random_key(default_length))
                .collect();
            logger.warn("⚠️ Salts generated automatically. Store them securely.");
            Ok(salts)
        }
        None => Err(AdvancedTokenError::Message(
            "Salt array cannot be empty or less than 2.".to_string(),
        )),
    }
}
