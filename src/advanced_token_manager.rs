mod crypto;
mod defaults;
mod env;
mod error;
mod init;
mod jwt;
mod native;
mod normalize;
mod options;
mod random;
mod salts;
mod secret;
mod time;
mod token;

use std::sync::Arc;

pub use error::{AdvancedTokenError, TokenValidationError};
pub use options::{
    AdvancedTokenManagerOptions, GenerateTokenOptions, ManagerSignJwtOptions,
    ManagerVerifyJwtOptions, ValidateTokenOptions,
};

use crate::jwt::JwtAlgorithm;

const DEFAULT_SECRET_LENGTH: usize = 32;
const DEFAULT_SALT_COUNT: usize = 10;
const DEFAULT_SALT_LENGTH: usize = 16;
const MIN_SECRET_LENGTH: usize = 16;
const MIN_SALT_COUNT: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

pub trait AdvancedTokenManagerLogger: Send + Sync {
    fn warn(&self, message: &str);
    fn error(&self, message: &str);
}

#[derive(Clone)]
struct DefaultLogger;

impl AdvancedTokenManagerLogger for DefaultLogger {
    fn warn(&self, message: &str) {
        eprintln!("{}", message);
    }

    fn error(&self, message: &str) {
        eprintln!("{}", message);
    }
}

pub struct ManagerConfig {
    pub secret: String,
    pub salts: Vec<String>,
}

pub struct AdvancedTokenManager {
    secret: String,
    salts: Vec<String>,
    algorithm: Algorithm,
    last_salt_index: Option<usize>,
    logger: Arc<dyn AdvancedTokenManagerLogger>,
    throw_on_validation_failure: bool,
    jwt_default_algorithms: Option<Vec<JwtAlgorithm>>,
    jwt_max_payload_size: Option<usize>,
    jwt_allowed_claims: Option<Vec<String>>,
}

impl AdvancedTokenManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret: Option<String>,
        salts: Option<Vec<String>>,
        algorithm: Option<Algorithm>,
        allow_auto_generate: bool,
        no_env: bool,
        options: Option<AdvancedTokenManagerOptions>,
    ) -> Result<Self, AdvancedTokenError> {
        let options = options.unwrap_or_default();
        let logger = options
            .logger
            .clone()
            .unwrap_or_else(|| Arc::new(DefaultLogger));
        let defaults = init::resolve_defaults(&options)?;
        let jwt_options = init::resolve_jwt_options(options)?;

        let secret = init::initialize_secret(
            secret,
            allow_auto_generate,
            no_env,
            defaults.secret_length,
            &*logger,
        )?;
        let salts = init::initialize_salts(
            salts,
            allow_auto_generate,
            no_env,
            defaults.salt_count,
            defaults.salt_length,
            &*logger,
        )?;

        Ok(Self {
            secret,
            salts,
            algorithm: algorithm.unwrap_or(Algorithm::Sha256),
            last_salt_index: None,
            logger,
            throw_on_validation_failure: jwt_options.throw_on_validation_failure,
            jwt_default_algorithms: jwt_options.default_algorithms,
            jwt_max_payload_size: jwt_options.max_payload_size,
            jwt_allowed_claims: jwt_options.allowed_claims,
        })
    }

    pub fn get_config(&self) -> ManagerConfig {
        ManagerConfig {
            secret: self.secret.clone(),
            salts: self.salts.clone(),
        }
    }
}
