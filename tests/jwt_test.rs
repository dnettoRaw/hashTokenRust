use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hash_token_rust::jwt::{
    sign_jwt, verify_jwt, verify_jwt_as, Audience, Issuer, JwtAlgorithm, JwtClaims, SignJwtOptions,
    VerifyJwtOptions,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

fn encode_json(value: Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
}

fn signed_hs256_token(payload: Value) -> String {
    let header = encode_json(json!({"alg": "HS256", "typ": "JWT"}));
    let payload = encode_json(payload);
    let signing_input = format!("{}.{}", header, payload);
    let mut mac = Hmac::<Sha256>::new_from_slice("secret-value".as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}.{}", signing_input, signature)
}

#[test]
fn sign_and_verify_jwt() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    payload.insert("aud".to_string(), "service".into());

    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            algorithm: Some(JwtAlgorithm::HS512),
            ..Default::default()
        },
    )
    .unwrap();

    let verified = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            algorithms: Some(vec![JwtAlgorithm::HS512]),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(verified.get("sub").unwrap(), "user-123");
}

#[test]
fn sign_and_verify_hs256() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());

    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            algorithm: Some(JwtAlgorithm::HS256),
            ..Default::default()
        },
    )
    .unwrap();

    let verified = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            algorithms: Some(vec![JwtAlgorithm::HS256]),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(verified.get("sub").unwrap(), "user-123");
}

#[test]
fn verify_rejects_invalid_signature() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let tampered = format!("{}tampered", token);
    let err = verify_jwt(
        &tampered,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("invalid signature")
            || message.contains("invalid token structure")
            || message.contains("malformed base64url"),
        "unexpected error message: {}",
        message
    );

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "wrong-secret".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("invalid signature") || message.contains("malformed base64url"),
        "unexpected error message: {}",
        message
    );
}

#[test]
fn verify_enforces_audience_and_issuer() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    payload.insert("aud".to_string(), "service-a".into());
    payload.insert("iss".to_string(), "issuer-a".into());

    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            audience: Some(Audience::Single("other".into())),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("audience mismatch"));

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            issuer: Some(Issuer::Single("other".into())),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("issuer mismatch"));
}

#[test]
fn verify_rejects_alg_none() {
    let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ.c2ln";
    let err = verify_jwt(
        token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("alg \"none\""));
}

#[test]
fn verify_rejects_unexpected_algorithm() {
    let token = format!(
        "{}.{}.{}",
        encode_json(json!({"alg": "RS256", "typ": "JWT"})),
        encode_json(json!({"sub": "123"})),
        "c2ln"
    );

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported algorithm"));

    let lower_alg_token = format!(
        "{}.{}.{}",
        encode_json(json!({"alg": "hs256", "typ": "JWT"})),
        encode_json(json!({"sub": "123"})),
        "c2ln"
    );
    let err = verify_jwt(
        &lower_alg_token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("unsupported algorithm"));
}

#[test]
fn verify_rejects_truncated_signature() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[2] = &parts[2][..parts[2].len() - 4];
    let truncated = parts.join(".");

    let err = verify_jwt(
        &truncated,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("invalid signature") || message.contains("malformed base64url"),
        "unexpected error message: {}",
        message
    );
}

#[test]
fn verify_enforces_temporal_claims() {
    let mut expired_payload = JwtClaims::new();
    expired_payload.insert("sub".to_string(), "user-123".into());
    expired_payload.insert("exp".to_string(), 900.into());

    let token = sign_jwt(
        &expired_payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(1000.0),
            ..Default::default()
        },
    )
    .unwrap();

    let expired = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(1001.0),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(expired.to_string().contains("token expired"));

    let mut nbf_payload = JwtClaims::new();
    nbf_payload.insert("sub".to_string(), "user-123".into());
    nbf_payload.insert("nbf".to_string(), 1100.into());
    let token = sign_jwt(
        &nbf_payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(1000.0),
            ..Default::default()
        },
    )
    .unwrap();
    let not_active = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(950.0),
            clock_tolerance: Some(100.0),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(not_active.to_string().contains("token not active yet"));

    let mut iat_payload = JwtClaims::new();
    iat_payload.insert("sub".to_string(), "user-123".into());
    iat_payload.insert("iat".to_string(), 1100.into());
    let token = sign_jwt(
        &iat_payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(1000.0),
            ..Default::default()
        },
    )
    .unwrap();
    let used_before_issued = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            clock_timestamp: Some(999.0),
            clock_tolerance: Some(100.0),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(used_before_issued
        .to_string()
        .contains("token used before issued"));
}

#[test]
fn verify_rejects_invalid_claim_shapes() {
    let token = signed_hs256_token(json!({"sub": ""}));

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            subject: Some("user-123".into()),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("non-empty string"));
}

#[test]
fn verify_rejects_payload_over_max_size() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    payload.insert("large".to_string(), "x".repeat(128).into());
    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            max_payload_size: Some(32),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("maxPayloadSize"));
}

#[test]
fn verify_rejects_disallowed_claims() {
    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    payload.insert("custom".to_string(), 42.into());

    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let err = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            allowed_claims: Some(vec!["other".into()]),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(err.to_string().contains("is not allowed"));
}

#[test]
fn deserialize_verified_payload() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Claims {
        sub: String,
        role: String,
    }

    let mut payload = JwtClaims::new();
    payload.insert("sub".to_string(), "user-123".into());
    payload.insert("role".to_string(), "admin".into());

    let token = sign_jwt(
        &payload,
        &SignJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    let claims: Claims = verify_jwt_as(
        &token,
        &VerifyJwtOptions {
            secret: "secret-value".to_string(),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        claims,
        Claims {
            sub: "user-123".into(),
            role: "admin".into()
        }
    );
}
