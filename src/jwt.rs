use std::collections::HashSet;
use std::fmt::{self, Display};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use sha2::{Sha256, Sha512};
use thiserror::Error;

const STANDARD_CLAIMS: [&str; 6] = ["iss", "sub", "aud", "exp", "nbf", "iat"];
const BASE64URL_ALLOWED: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub type JwtClaims = Map<String, Value>;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    HS256,
    HS512,
}

impl JwtAlgorithm {}

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

#[derive(Debug, Error)]
#[error("{message}")]
pub struct JwtError {
    message: String,
}

impl JwtError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn claim_conflict(claim: &str) -> Self {
        Self::new(format!(
            "JWT: claim \"{}\" already present with a different value.",
            claim
        ))
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
    fn into_vec(self) -> Result<Vec<String>, JwtError> {
        match self {
            Audience::Single(value) => {
                let normalized = normalize_string(value, "Audience")?;
                Ok(vec![normalized])
            }
            Audience::Multiple(values) => {
                if values.is_empty() {
                    return Err(JwtError::new("JWT: audience array must not be empty."));
                }
                let mut normalized = Vec::with_capacity(values.len());
                for value in values {
                    normalized.push(normalize_string(value, "Audience")?);
                }
                Ok(normalized)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum Issuer {
    Single(String),
    Multiple(Vec<String>),
}

impl Issuer {
    fn into_vec(self) -> Result<Vec<String>, JwtError> {
        match self {
            Issuer::Single(value) => Ok(vec![normalize_string(value, "Issuer")?]),
            Issuer::Multiple(values) => {
                if values.is_empty() {
                    return Err(JwtError::new("JWT: issuer array must not be empty."));
                }
                let mut normalized = Vec::with_capacity(values.len());
                for value in values {
                    normalized.push(normalize_string(value, "Issuer")?);
                }
                Ok(normalized)
            }
        }
    }
}

pub fn sign_jwt(payload: &JwtClaims, options: &SignJwtOptions) -> Result<String, JwtError> {
    if options.secret.trim().is_empty() {
        return Err(JwtError::new(
            "JWT: a non-empty secret is required to sign.",
        ));
    }

    let algorithm = options.algorithm.unwrap_or(JwtAlgorithm::HS256);
    let header = build_header(options, algorithm)?;

    let timestamp = current_timestamp(options.clock_timestamp)?;
    let mut claims = payload.clone();

    apply_issued_at(&mut claims, options.issued_at, timestamp)?;
    apply_expires_in(&mut claims, options.expires_in, timestamp)?;
    apply_not_before(&mut claims, options.not_before, timestamp)?;
    apply_audience(&mut claims, options.audience.clone())?;
    apply_issuer(&mut claims, options.issuer.clone())?;
    apply_subject(&mut claims, options.subject.clone())?;

    let header_json = serde_json::to_vec(&header)
        .map_err(|_| JwtError::new("JWT: failed to serialize header."))?;
    let payload_json = serde_json::to_vec(&Value::Object(claims.clone()))
        .map_err(|_| JwtError::new("JWT: failed to serialize payload."))?;
    let encoded_header = base64url_encode(header_json);
    let encoded_payload = base64url_encode(payload_json);
    let signing_input = format!("{}.{}", &encoded_header, &encoded_payload);
    let signature = create_signature(algorithm, &options.secret, &signing_input)?;

    Ok(format!(
        "{}.{}.{}",
        encoded_header, encoded_payload, signature
    ))
}

pub fn verify_jwt(token: &str, options: &VerifyJwtOptions) -> Result<JwtClaims, JwtError> {
    if token.trim().is_empty() {
        return Err(JwtError::new("JWT: token must be a non-empty string."));
    }
    if options.secret.trim().is_empty() {
        return Err(JwtError::new(
            "JWT: a non-empty secret is required to verify.",
        ));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(JwtError::new("JWT: invalid token structure."));
    }

    let encoded_header = parts[0];
    let encoded_payload = parts[1];
    let encoded_signature = parts[2];

    let header_bytes = base64url_decode(encoded_header, "header")?;
    let header_value: Value = serde_json::from_slice(&header_bytes)
        .map_err(|_| JwtError::new("JWT: invalid header JSON."))?;
    let header_obj = header_value
        .as_object()
        .ok_or_else(|| JwtError::new("JWT: header must be a JSON object."))?;

    let alg_value = header_obj
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| JwtError::new("JWT: missing algorithm."))?;

    if alg_value.eq_ignore_ascii_case("none") {
        return Err(JwtError::new(
            "JWT: unsigned tokens (alg \"none\") are not allowed.",
        ));
    }

    let algorithm = JwtAlgorithm::from_str(alg_value.to_ascii_uppercase().as_str())?;

    if let Some(allowed) = &options.algorithms {
        if !allowed.contains(&algorithm) {
            return Err(JwtError::new(format!(
                "JWT: algorithm {} is not allowed.",
                algorithm
            )));
        }
    }

    if let Some(typ_value) = header_obj.get("typ") {
        let typ = typ_value
            .as_str()
            .ok_or_else(|| JwtError::new("JWT: header type must be a string."))?;
        if typ != "JWT" {
            return Err(JwtError::new("JWT: header type must be \"JWT\"."));
        }
    }

    let payload_bytes = base64url_decode(encoded_payload, "payload")?;
    if let Some(max_size) = options.max_payload_size {
        if payload_bytes.len() > max_size {
            return Err(JwtError::new("JWT: payload exceeds maxPayloadSize."));
        }
    }

    let payload_value: Value = serde_json::from_slice(&payload_bytes)
        .map_err(|_| JwtError::new("JWT: invalid payload JSON."))?;
    let payload = payload_value
        .as_object()
        .cloned()
        .ok_or_else(|| JwtError::new("JWT: payload must be a JSON object."))?;

    if let Some(allowed_claims) = &options.allowed_claims {
        enforce_allowed_claims(&payload, allowed_claims)?;
    }

    verify_signature(
        algorithm,
        &options.secret,
        encoded_header,
        encoded_payload,
        encoded_signature,
    )?;

    validate_temporal_claims(&payload, options)?;
    validate_audience(&payload, options)?;
    validate_issuer(&payload, options)?;
    validate_subject(&payload, options)?;

    Ok(payload)
}

pub fn verify_jwt_as<T: DeserializeOwned>(
    token: &str,
    options: &VerifyJwtOptions,
) -> Result<T, JwtError> {
    let claims = verify_jwt(token, options)?;
    serde_json::from_value(Value::Object(claims))
        .map_err(|_| JwtError::new("JWT: payload could not be deserialized into target type."))
}

fn build_header(options: &SignJwtOptions, algorithm: JwtAlgorithm) -> Result<JwtClaims, JwtError> {
    let mut header = match &options.header {
        Some(custom) => custom.clone(),
        None => Map::new(),
    };

    if let Some(alg) = header.get("alg") {
        if alg.as_str() != Some(&algorithm.to_string()) {
            return Err(JwtError::new("JWT: header algorithm mismatch."));
        }
    }

    if let Some(typ) = header.get("typ") {
        if typ.as_str() != Some("JWT") {
            return Err(JwtError::new("JWT: header type must be \"JWT\"."));
        }
    }

    header.insert("alg".to_string(), Value::String(algorithm.to_string()));
    header.insert("typ".to_string(), Value::String("JWT".to_string()));

    Ok(header)
}

fn apply_issued_at(
    claims: &mut JwtClaims,
    issued_at: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = issued_at {
        let normalized = normalize_number(value, "iat")?;
        enforce_claim(claims, "iat", Value::from(normalized))
    } else if let Some(existing) = claims.get("iat") {
        ensure_numeric(existing, "iat")?;
        Ok(())
    } else {
        claims.insert("iat".to_string(), Value::from(timestamp));
        Ok(())
    }
}

fn apply_expires_in(
    claims: &mut JwtClaims,
    expires_in: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = expires_in {
        if !value.is_finite() || value <= 0.0 {
            return Err(JwtError::new(
                "JWT: expiresIn must be a positive number of seconds.",
            ));
        }
        let exp = timestamp + value.floor() as i64;
        enforce_claim(claims, "exp", Value::from(exp))
    } else if let Some(existing) = claims.get("exp") {
        ensure_numeric(existing, "exp")
    } else {
        Ok(())
    }
}

fn apply_not_before(
    claims: &mut JwtClaims,
    not_before: Option<f64>,
    timestamp: i64,
) -> Result<(), JwtError> {
    if let Some(value) = not_before {
        if !value.is_finite() {
            return Err(JwtError::new("JWT: notBefore must be a number of seconds."));
        }
        let nbf = timestamp + value.floor() as i64;
        enforce_claim(claims, "nbf", Value::from(nbf))
    } else if let Some(existing) = claims.get("nbf") {
        ensure_numeric(existing, "nbf")
    } else {
        Ok(())
    }
}

fn apply_audience(claims: &mut JwtClaims, audience: Option<Audience>) -> Result<(), JwtError> {
    if let Some(audience) = audience {
        let audiences = audience.into_vec()?;
        let value = if audiences.len() == 1 {
            Value::String(audiences[0].clone())
        } else {
            Value::Array(audiences.into_iter().map(Value::String).collect())
        };
        enforce_claim(claims, "aud", value)
    } else if let Some(existing) = claims.get("aud") {
        if existing.is_array() {
            normalize_audience_array(existing)?;
        } else {
            ensure_string(existing, "aud")?;
        }
        Ok(())
    } else {
        Ok(())
    }
}

fn apply_issuer(claims: &mut JwtClaims, issuer: Option<String>) -> Result<(), JwtError> {
    if let Some(issuer) = issuer {
        let normalized = normalize_string(issuer, "Issuer")?;
        enforce_claim(claims, "iss", Value::String(normalized))
    } else if let Some(existing) = claims.get("iss") {
        ensure_string(existing, "iss")
    } else {
        Ok(())
    }
}

fn apply_subject(claims: &mut JwtClaims, subject: Option<String>) -> Result<(), JwtError> {
    if let Some(subject) = subject {
        let normalized = normalize_string(subject, "Subject")?;
        enforce_claim(claims, "sub", Value::String(normalized))
    } else if let Some(existing) = claims.get("sub") {
        ensure_string(existing, "sub")
    } else {
        Ok(())
    }
}

fn enforce_claim(claims: &mut JwtClaims, key: &str, value: Value) -> Result<(), JwtError> {
    match claims.get(key) {
        Some(existing) if *existing != value => Err(JwtError::claim_conflict(key)),
        Some(_) => Ok(()),
        None => {
            claims.insert(key.to_string(), value);
            Ok(())
        }
    }
}

fn ensure_numeric(value: &Value, claim: &str) -> Result<(), JwtError> {
    match value {
        Value::Number(number) if number.as_i64().is_some() => Ok(()),
        _ => Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a finite number.",
            claim
        ))),
    }
}

fn ensure_string(value: &Value, claim: &str) -> Result<(), JwtError> {
    match value {
        Value::String(text) if !text.is_empty() => Ok(()),
        _ => Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a non-empty string.",
            claim
        ))),
    }
}

fn normalize_audience_array(value: &Value) -> Result<Vec<String>, JwtError> {
    let items = value
        .as_array()
        .ok_or_else(|| JwtError::new("JWT: audience must be an array of strings."))?;
    if items.is_empty() {
        return Err(JwtError::new("JWT: audience array must not be empty."));
    }
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        let string = item
            .as_str()
            .ok_or_else(|| JwtError::new("JWT: audience must be an array of strings."))?;
        if string.is_empty() {
            return Err(JwtError::new("JWT: audience must be an array of strings."));
        }
        normalized.push(string.to_string());
    }
    Ok(normalized)
}

fn enforce_allowed_claims(payload: &JwtClaims, allowed_claims: &[String]) -> Result<(), JwtError> {
    let mut normalized = HashSet::new();
    for claim in allowed_claims {
        let trimmed = claim.trim();
        if trimmed.is_empty() {
            return Err(JwtError::new(
                "JWT: allowedClaims must be an array of non-empty strings.",
            ));
        }
        normalized.insert(trimmed.to_string());
    }

    for key in payload.keys() {
        if STANDARD_CLAIMS.contains(&key.as_str()) {
            continue;
        }
        if !normalized.contains(key) {
            return Err(JwtError::new(format!(
                "JWT: claim \"{}\" is not allowed.",
                key
            )));
        }
    }
    Ok(())
}

fn verify_signature(
    algorithm: JwtAlgorithm,
    secret: &str,
    encoded_header: &str,
    encoded_payload: &str,
    encoded_signature: &str,
) -> Result<(), JwtError> {
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let provided_signature = base64url_decode(encoded_signature, "signature")?;
    let expected_signature = create_signature_buffer(algorithm, secret, &signing_input)?;

    constant_time_compare(&expected_signature, &provided_signature)
}

fn create_signature(
    algorithm: JwtAlgorithm,
    secret: &str,
    signing_input: &str,
) -> Result<String, JwtError> {
    let bytes = create_signature_buffer(algorithm, secret, signing_input)?;
    Ok(base64url_encode(bytes))
}

fn constant_time_compare(expected: &[u8], provided: &[u8]) -> Result<(), JwtError> {
    if expected.len() != provided.len() {
        return Err(JwtError::new("JWT: invalid signature."));
    }

    let mut diff: u8 = 0;
    for (a, b) in expected.iter().zip(provided) {
        diff |= a ^ b;
    }

    if diff == 0 {
        Ok(())
    } else {
        Err(JwtError::new("JWT: invalid signature."))
    }
}

fn create_signature_buffer(
    algorithm: JwtAlgorithm,
    secret: &str,
    signing_input: &str,
) -> Result<Vec<u8>, JwtError> {
    match algorithm {
        JwtAlgorithm::HS256 => compute_hmac_sha256(secret, signing_input),
        JwtAlgorithm::HS512 => compute_hmac_sha512(secret, signing_input),
    }
}

fn compute_hmac_sha256(secret: &str, signing_input: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| JwtError::new("JWT: failed to create HMAC instance."))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn compute_hmac_sha512(secret: &str, signing_input: &str) -> Result<Vec<u8>, JwtError> {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .map_err(|_| JwtError::new("JWT: failed to create HMAC instance."))?;
    mac.update(signing_input.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn current_timestamp(clock: Option<f64>) -> Result<i64, JwtError> {
    if let Some(value) = clock {
        if !value.is_finite() {
            return Err(JwtError::new(
                "JWT: clockTimestamp must be a finite number.",
            ));
        }
        return Ok(value.floor() as i64);
    }
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JwtError::new("JWT: system time before UNIX_EPOCH."))?;
    Ok(duration.as_secs() as i64)
}

fn normalize_number(value: f64, claim: &str) -> Result<i64, JwtError> {
    if !value.is_finite() {
        return Err(JwtError::new(format!(
            "JWT: Claim \"{}\" must be a finite number.",
            claim
        )));
    }
    Ok(value.floor() as i64)
}

fn normalize_string(value: String, context: &str) -> Result<String, JwtError> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(JwtError::new(format!(
            "JWT: {} must be a non-empty string.",
            context
        )));
    }
    Ok(trimmed)
}

fn base64url_encode<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn base64url_decode(input: &str, part: &str) -> Result<Vec<u8>, JwtError> {
    if !input.bytes().all(|byte| BASE64URL_ALLOWED.contains(&byte)) {
        return Err(JwtError::new(format!(
            "JWT: invalid base64url encoding in {}.",
            part
        )));
    }

    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| JwtError::new(format!("JWT: malformed base64url segment in {}.", part)))?;

    if base64url_encode(&decoded) != input.trim_end_matches('=') {
        return Err(JwtError::new(format!(
            "JWT: malformed base64url segment in {}.",
            part
        )));
    }

    Ok(decoded)
}

fn validate_temporal_claims(
    payload: &JwtClaims,
    options: &VerifyJwtOptions,
) -> Result<(), JwtError> {
    let now = current_timestamp(options.clock_timestamp)?;
    let tolerance = match options.clock_tolerance {
        Some(value) if value.is_finite() && value >= 0.0 => value,
        Some(_) => {
            return Err(JwtError::new(
                "JWT: clockTolerance must be a non-negative number.",
            ))
        }
        None => 0.0,
    };
    let tolerance = tolerance.floor() as i64;

    if let Some(exp) = payload.get("exp") {
        ensure_numeric(exp, "exp")?;
        let exp_value = exp.as_i64().unwrap();
        if now > exp_value + tolerance {
            return Err(JwtError::new("JWT: token expired."));
        }
    }

    if let Some(nbf) = payload.get("nbf") {
        ensure_numeric(nbf, "nbf")?;
        let nbf_value = nbf.as_i64().unwrap();
        if now + tolerance < nbf_value {
            return Err(JwtError::new("JWT: token not active yet."));
        }
    }

    if let Some(iat) = payload.get("iat") {
        ensure_numeric(iat, "iat")?;
        let iat_value = iat.as_i64().unwrap();
        if iat_value - tolerance > now {
            return Err(JwtError::new("JWT: token used before issued."));
        }
    }

    if let Some(max_age) = options.max_age {
        if !max_age.is_finite() || max_age <= 0.0 {
            return Err(JwtError::new(
                "JWT: maxAge must be a positive number of seconds.",
            ));
        }
        let max_age = max_age.floor() as i64;
        let iat = payload
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| JwtError::new("JWT: cannot apply maxAge without an \"iat\" claim."))?;
        if now - iat - tolerance > max_age {
            return Err(JwtError::new("JWT: token exceeds maxAge."));
        }
    }

    Ok(())
}

fn validate_audience(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("aud").is_none() && options.audience.is_none() {
        return Ok(());
    }

    let token_audience = match payload.get("aud") {
        Some(value) => {
            if value.is_array() {
                normalize_audience_array(value)?
            } else {
                ensure_string(value, "aud")?;
                vec![value.as_str().unwrap().to_string()]
            }
        }
        None => return Err(JwtError::new("JWT: missing required audience claim.")),
    };

    if let Some(audience) = options.audience.clone() {
        let expected = audience.into_vec()?;
        if !expected
            .iter()
            .any(|value| token_audience.iter().any(|aud| aud == value))
        {
            return Err(JwtError::new("JWT: audience mismatch."));
        }
    }

    Ok(())
}

fn validate_issuer(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("iss").is_none() && options.issuer.is_none() {
        return Ok(());
    }

    let issuer = match payload.get("iss") {
        Some(value) => {
            ensure_string(value, "iss")?;
            value.as_str().unwrap().to_string()
        }
        None => return Err(JwtError::new("JWT: missing required issuer claim.")),
    };

    if let Some(issuer_option) = options.issuer.clone() {
        let allowed = issuer_option.into_vec()?;
        if !allowed.contains(&issuer) {
            return Err(JwtError::new("JWT: issuer mismatch."));
        }
    }

    Ok(())
}

fn validate_subject(payload: &JwtClaims, options: &VerifyJwtOptions) -> Result<(), JwtError> {
    if payload.get("sub").is_none() && options.subject.is_none() {
        return Ok(());
    }

    let subject = match payload.get("sub") {
        Some(value) => {
            ensure_string(value, "sub")?;
            value.as_str().unwrap().to_string()
        }
        None => return Err(JwtError::new("JWT: missing required subject claim.")),
    };

    if let Some(expected) = &options.subject {
        let normalized = normalize_string(expected.clone(), "Subject")?;
        if subject != normalized {
            return Err(JwtError::new("JWT: subject mismatch."));
        }
    }

    Ok(())
}
