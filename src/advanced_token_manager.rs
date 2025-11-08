use std::env;
use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use rand::distributions::{Distribution, Uniform};
use rand::{rngs::OsRng, Rng};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use thiserror::Error;

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::jwt::{
    sign_jwt, verify_jwt_as, Audience, Issuer, JwtAlgorithm, JwtClaims, JwtError, SignJwtOptions,
    VerifyJwtOptions,
};

const DEFAULT_SECRET_LENGTH: usize = 32;
const DEFAULT_SALT_COUNT: usize = 10;
const DEFAULT_SALT_LENGTH: usize = 16;
const MIN_SECRET_LENGTH: usize = 16;
const MIN_SALT_COUNT: usize = 2;
const CHARACTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    fn to_hmac(self, secret: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenValidationError> {
        match self {
            Algorithm::Sha256 => compute_hmac_sha256(secret, input),
            Algorithm::Sha512 => compute_hmac_sha512(secret, input),
        }
    }
}

#[derive(Debug, Error)]
pub enum AdvancedTokenError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Jwt(#[from] JwtError),
}

#[derive(Debug, Error, Clone)]
pub enum TokenValidationError {
    #[error("{0}")]
    Message(String),
}

impl TokenValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
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

#[derive(Default, Clone)]
pub struct AdvancedTokenManagerOptions {
    pub logger: Option<Arc<dyn AdvancedTokenManagerLogger>>,
    pub jwt_default_algorithms: Option<Vec<JwtAlgorithm>>,
    pub default_secret_length: Option<usize>,
    pub default_salt_count: Option<usize>,
    pub default_salt_length: Option<usize>,
    pub throw_on_validation_failure: Option<bool>,
    pub jwt_max_payload_size: Option<usize>,
    pub jwt_allowed_claims: Option<Vec<String>>,
}

#[derive(Default, Clone)]
pub struct ValidateTokenOptions {
    pub throw_on_failure: Option<bool>,
}

#[derive(Default, Clone)]
pub struct ManagerSignJwtOptions {
    pub secret: Option<String>,
    pub algorithm: Option<JwtAlgorithm>,
    pub header: Option<Map<String, Value>>,
    pub expires_in: Option<f64>,
    pub not_before: Option<f64>,
    pub audience: Option<Audience>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub issued_at: Option<f64>,
    pub clock_timestamp: Option<f64>,
}

#[derive(Default, Clone)]
pub struct ManagerVerifyJwtOptions {
    pub secret: Option<String>,
    pub algorithms: Option<Vec<JwtAlgorithm>>,
    pub clock_tolerance: Option<f64>,
    pub audience: Option<Audience>,
    pub issuer: Option<Issuer>,
    pub subject: Option<String>,
    pub max_age: Option<f64>,
    pub clock_timestamp: Option<f64>,
    pub max_payload_size: Option<usize>,
    pub allowed_claims: Option<Vec<String>>,
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
        let logger = options.logger.unwrap_or_else(|| Arc::new(DefaultLogger));

        let default_secret_length = resolve_length_option(
            "defaultSecretLength",
            options.default_secret_length,
            DEFAULT_SECRET_LENGTH,
            MIN_SECRET_LENGTH,
        )?;
        let default_salt_count = resolve_length_option(
            "defaultSaltCount",
            options.default_salt_count,
            DEFAULT_SALT_COUNT,
            MIN_SALT_COUNT,
        )?;
        let default_salt_length = resolve_length_option(
            "defaultSaltLength",
            options.default_salt_length,
            DEFAULT_SALT_LENGTH,
            1,
        )?;
        let jwt_default_algorithms = normalize_algorithms(options.jwt_default_algorithms)?;
        let throw_on_validation_failure = options.throw_on_validation_failure.unwrap_or(false);
        let jwt_max_payload_size =
            normalize_positive_usize("jwtMaxPayloadSize", options.jwt_max_payload_size)?;
        let jwt_allowed_claims = normalize_allowed_claims(options.jwt_allowed_claims)?;

        let secret = initialize_secret(
            secret,
            allow_auto_generate,
            no_env,
            default_secret_length,
            &*logger,
        )?;
        let salts = initialize_salts(
            salts,
            allow_auto_generate,
            no_env,
            default_salt_count,
            default_salt_length,
            &*logger,
        )?;
        let algorithm = algorithm.unwrap_or(Algorithm::Sha256);

        Ok(Self {
            secret,
            salts,
            algorithm,
            last_salt_index: None,
            logger,
            throw_on_validation_failure,
            jwt_default_algorithms,
            jwt_max_payload_size,
            jwt_allowed_claims,
        })
    }

    pub fn generate_token(
        &mut self,
        input: &str,
        salt_index: Option<usize>,
    ) -> Result<String, TokenValidationError> {
        let index = match salt_index {
            Some(index) => {
                self.validate_salt_index(index)?;
                index
            }
            None => self.get_random_salt_index(),
        };
        let salt = &self.salts[index];
        let checksum = self.create_checksum(input, salt)?;
        Ok(general_purpose::STANDARD.encode(format!("{}|{}|{}", input, index, checksum)))
    }

    pub fn validate_token(&self, token: &str) -> Result<Option<String>, TokenValidationError> {
        self.validate_token_with_options(token, None)
    }

    pub fn validate_token_with_options(
        &self,
        token: &str,
        options: Option<ValidateTokenOptions>,
    ) -> Result<Option<String>, TokenValidationError> {
        let options = options.unwrap_or_default();
        let should_throw = options
            .throw_on_failure
            .unwrap_or(self.throw_on_validation_failure);

        match self.validate_token_internal(token) {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                self.logger
                    .error(&format!("Error validating token: {}", error));
                if should_throw {
                    Err(error)
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn validate_token_lenient(&self, token: &str) -> Option<String> {
        self.validate_token_with_options(
            token,
            Some(ValidateTokenOptions {
                throw_on_failure: Some(false),
            }),
        )
        .ok()
        .flatten()
    }

    pub fn extract_data(&self, token: &str) -> Result<Option<String>, TokenValidationError> {
        self.validate_token(token)
    }

    pub fn generate_jwt(
        &self,
        payload: &JwtClaims,
        options: Option<ManagerSignJwtOptions>,
    ) -> Result<String, AdvancedTokenError> {
        let options = options.unwrap_or_default();
        let secret = options.secret.unwrap_or_else(|| self.secret.clone());
        let sign_options = SignJwtOptions {
            secret,
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
        let secret = options.secret.unwrap_or_else(|| self.secret.clone());
        let verify_options = VerifyJwtOptions {
            secret,
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

    pub fn get_config(&self) -> ManagerConfig {
        ManagerConfig {
            secret: self.secret.clone(),
            salts: self.salts.clone(),
        }
    }

    fn validate_token_internal(&self, token: &str) -> Result<String, TokenValidationError> {
        let decoded = general_purpose::STANDARD
            .decode(token)
            .map_err(|_| TokenValidationError::new("Invalid base64 token."))?;
        let decoded = String::from_utf8(decoded)
            .map_err(|_| TokenValidationError::new("Token is not valid UTF-8."))?;
        let mut parts = decoded.split('|');
        let input = parts
            .next()
            .ok_or_else(|| TokenValidationError::new("Token missing payload."))?;
        let salt_index = parts
            .next()
            .ok_or_else(|| TokenValidationError::new("Token missing salt index."))?;
        let checksum = parts
            .next()
            .ok_or_else(|| TokenValidationError::new("Token missing checksum."))?;

        if parts.next().is_some() {
            return Err(TokenValidationError::new(
                "Token has unexpected extra data.",
            ));
        }

        let index: usize = salt_index
            .parse()
            .map_err(|_| TokenValidationError::new("Token has invalid salt index."))?;
        self.validate_salt_index(index)?;
        let expected_checksum = self.create_checksum(input, &self.salts[index])?;
        if expected_checksum == checksum {
            Ok(input.to_string())
        } else {
            Err(TokenValidationError::new("Checksum mismatch."))
        }
    }

    fn validate_salt_index(&self, index: usize) -> Result<(), TokenValidationError> {
        if index < self.salts.len() {
            Ok(())
        } else {
            Err(TokenValidationError::new(format!(
                "Invalid salt index: {}",
                index
            )))
        }
    }

    fn create_checksum(&self, input: &str, salt: &str) -> Result<String, TokenValidationError> {
        let mut payload = String::with_capacity(input.len() + salt.len());
        payload.push_str(input);
        payload.push_str(salt);
        let digest = self
            .algorithm
            .to_hmac(self.secret.as_bytes(), payload.as_bytes())?;
        Ok(hex::encode(digest))
    }

    fn get_random_salt_index(&mut self) -> usize {
        let len = self.salts.len();
        let mut rng = rand::thread_rng();
        loop {
            let index = rng.gen_range(0..len);
            if Some(index) != self.last_salt_index {
                self.last_salt_index = Some(index);
                return index;
            }
        }
    }
}

fn compute_hmac_sha256(secret: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenValidationError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| TokenValidationError::new("Invalid HMAC key."))?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_hmac_sha512(secret: &[u8], input: &[u8]) -> Result<Vec<u8>, TokenValidationError> {
    let mut mac = HmacSha512::new_from_slice(secret)
        .map_err(|_| TokenValidationError::new("Invalid HMAC key."))?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn initialize_secret(
    secret: Option<String>,
    allow_auto_generate: bool,
    no_env: bool,
    default_length: usize,
    logger: &dyn AdvancedTokenManagerLogger,
) -> Result<String, AdvancedTokenError> {
    let mut candidate = secret.map(|value| value.trim().to_string());

    if !no_env && candidate.is_none() {
        candidate = env::var("TOKEN_SECRET")
            .ok()
            .map(|value| value.trim().to_string());
    }

    if let Some(secret) = candidate {
        if secret.len() < MIN_SECRET_LENGTH {
            return Err(AdvancedTokenError::Message(format!(
                "Secret must be at least {} characters long.",
                MIN_SECRET_LENGTH
            )));
        }
        Ok(secret)
    } else if allow_auto_generate {
        let generated = generate_random_key(default_length);
        logger.warn("⚠️ Secret generated automatically. Store it securely.");
        Ok(generated)
    } else {
        Err(AdvancedTokenError::Message(format!(
            "Secret must be at least {} characters long.",
            MIN_SECRET_LENGTH
        )))
    }
}

fn initialize_salts(
    salts: Option<Vec<String>>,
    allow_auto_generate: bool,
    no_env: bool,
    default_count: usize,
    default_length: usize,
    logger: &dyn AdvancedTokenManagerLogger,
) -> Result<Vec<String>, AdvancedTokenError> {
    let mut resolved = salts;
    if !no_env {
        if resolved.as_ref().map_or(true, |values| values.is_empty()) {
            if let Ok(value) = env::var("TOKEN_SALTS") {
                resolved = Some(
                    value
                        .split(',')
                        .map(|entry| entry.trim().to_string())
                        .collect(),
                );
            }
        }
    }

    if let Some(values) = resolved {
        let sanitized: Vec<String> = values
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect();
        if sanitized.len() < MIN_SALT_COUNT {
            return Err(AdvancedTokenError::Message(format!(
                "Salt array cannot be empty or less than {}.",
                MIN_SALT_COUNT
            )));
        }
        Ok(sanitized)
    } else if allow_auto_generate {
        let salts: Vec<String> = (0..default_count)
            .map(|_| generate_random_key(default_length))
            .collect();
        logger.warn("⚠️ Salts generated automatically. Store them securely.");
        Ok(salts)
    } else {
        Err(AdvancedTokenError::Message(
            "Salt array cannot be empty or less than 2.".to_string(),
        ))
    }
}

fn resolve_length_option(
    name: &str,
    provided: Option<usize>,
    fallback: usize,
    minimum: usize,
) -> Result<usize, AdvancedTokenError> {
    match provided {
        None => Ok(fallback),
        Some(value) if value < minimum => Err(AdvancedTokenError::Message(format!(
            "{} must be an integer greater than or equal to {}.",
            name, minimum
        ))),
        Some(value) => Ok(value),
    }
}

fn normalize_positive_usize(
    name: &str,
    value: Option<usize>,
) -> Result<Option<usize>, AdvancedTokenError> {
    match value {
        None => Ok(None),
        Some(0) => Err(AdvancedTokenError::Message(format!(
            "{} must be a positive number.",
            name
        ))),
        Some(value) => Ok(Some(value)),
    }
}

fn normalize_allowed_claims(
    allowed: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, AdvancedTokenError> {
    match allowed {
        None => Ok(None),
        Some(values) => {
            let mut unique = Vec::new();
            for value in values {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    return Err(AdvancedTokenError::Message(
                        "jwtAllowedClaims must be an array of non-empty strings.".to_string(),
                    ));
                }
                if !unique.contains(&trimmed) {
                    unique.push(trimmed);
                }
            }
            Ok(Some(unique))
        }
    }
}

fn normalize_algorithms(
    algorithms: Option<Vec<JwtAlgorithm>>,
) -> Result<Option<Vec<JwtAlgorithm>>, AdvancedTokenError> {
    match algorithms {
        None => Ok(None),
        Some(values) => {
            if values.is_empty() {
                return Err(AdvancedTokenError::Message(
                    "jwtDefaultAlgorithms must be a non-empty array when provided.".to_string(),
                ));
            }
            let mut unique = Vec::new();
            for value in values {
                if !unique.contains(&value) {
                    unique.push(value);
                }
            }
            Ok(Some(unique))
        }
    }
}

fn generate_random_key(length: usize) -> String {
    let distribution = Uniform::from(0..CHARACTERS.len());
    let mut rng = OsRng;
    (0..length)
        .map(|_| CHARACTERS[distribution.sample(&mut rng)] as char)
        .collect()
}
