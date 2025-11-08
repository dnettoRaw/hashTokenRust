use hash_token_rust::jwt::{
    sign_jwt, verify_jwt, verify_jwt_as, Audience, Issuer, JwtAlgorithm, JwtClaims, SignJwtOptions,
    VerifyJwtOptions,
};

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
    assert!(err.to_string().contains("invalid signature"));
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
