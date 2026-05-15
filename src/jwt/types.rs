use std::fmt::{self, Display};
use std::str::FromStr;

use serde_json::{Map, Value};

use super::claims::normalize_string;
use super::JwtError;

pub type JwtClaims = Map<String, Value>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    HS256,
    HS512,
}

impl Display for JwtAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtAlgorithm::HS256 => write!(f, "HS256"),
            JwtAlgorithm::HS512 => write!(f, "HS512"),
        }
    }
}

impl FromStr for JwtAlgorithm {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "HS256" => Ok(JwtAlgorithm::HS256),
            "HS512" => Ok(JwtAlgorithm::HS512),
            other => Err(JwtError::new(format!(
                "JWT: unsupported algorithm: {}.",
                other
            ))),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SignJwtOptions {
    pub secret: String,
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

#[derive(Clone, Debug, Default)]
pub struct VerifyJwtOptions {
    pub secret: String,
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

#[derive(Clone, Debug)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    pub(super) fn into_vec(self) -> Result<Vec<String>, JwtError> {
        match self {
            Audience::Single(value) => Ok(vec![normalize_string(value, "Audience")?]),
            Audience::Multiple(values) => normalize_non_empty_strings(values, "Audience"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Issuer {
    Single(String),
    Multiple(Vec<String>),
}

impl Issuer {
    pub(super) fn into_vec(self) -> Result<Vec<String>, JwtError> {
        match self {
            Issuer::Single(value) => Ok(vec![normalize_string(value, "Issuer")?]),
            Issuer::Multiple(values) => normalize_non_empty_strings(values, "Issuer"),
        }
    }
}

fn normalize_non_empty_strings(
    values: Vec<String>,
    context: &str,
) -> Result<Vec<String>, JwtError> {
    if values.is_empty() {
        return Err(JwtError::new(format!(
            "JWT: {} array must not be empty.",
            context.to_lowercase()
        )));
    }

    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        normalized.push(normalize_string(value, context)?);
    }
    Ok(normalized)
}
