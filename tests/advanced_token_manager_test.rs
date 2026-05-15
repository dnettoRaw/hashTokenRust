use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hash_token_rust::advanced_token_manager::{
    AdvancedTokenManager, AdvancedTokenManagerOptions, Algorithm, GenerateTokenOptions,
    ManagerSignJwtOptions, ManagerVerifyJwtOptions, ValidateTokenOptions,
};
use hash_token_rust::jwt::{Audience, JwtAlgorithm, JwtClaims};

fn manager() -> AdvancedTokenManager {
    AdvancedTokenManager::new(
        Some("averysecuresecretvalue".to_string()),
        Some(vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ]),
        Some(Algorithm::Sha256),
        true,
        true,
        Some(AdvancedTokenManagerOptions::default()),
    )
    .unwrap()
}

#[test]
fn generate_and_validate_token() {
    let mut manager = manager();
    let token = manager.generate_token("payload-data", None).unwrap();
    let result = manager.validate_token(&token).unwrap();
    assert_eq!(result, Some("payload-data".to_string()));
}

#[test]
fn validate_token_lenient_failure_returns_none() {
    let mut manager = manager();
    let token = manager.generate_token("payload", None).unwrap();
    let tampered = format!("{}x", token);
    assert!(manager.validate_token(&tampered).unwrap().is_none());
    assert!(manager.validate_token_lenient(&tampered).is_none());
}

#[test]
fn validate_token_throws_when_configured() {
    let mut manager = AdvancedTokenManager::new(
        Some("averysecuresecretvalue".to_string()),
        Some(vec!["salt-a".into(), "salt-b".into()]),
        Some(Algorithm::Sha256),
        true,
        true,
        Some(AdvancedTokenManagerOptions {
            throw_on_validation_failure: Some(true),
            ..Default::default()
        }),
    )
    .unwrap();

    let token = manager.generate_token("payload", None).unwrap();
    let broken = format!("{}x", token);
    let err = manager.validate_token(&broken).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("Checksum mismatch") || message.contains("Invalid base64 token"),
        "unexpected error message: {}",
        message
    );
}

#[test]
fn generate_token_with_explicit_salt_index() {
    let mut manager = manager();
    let token = manager.generate_token("payload", Some(1)).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts[0], "htr1");
    let meta = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&meta).unwrap();
    assert_eq!(meta["salt"], 1);
}

#[test]
fn native_token_enforces_expiration() {
    let mut manager = manager();
    let token = manager
        .generate_token_with_options(
            "payload",
            Some(GenerateTokenOptions {
                expires_in: Some(10.0),
                issued_at: Some(1000.0),
                ..Default::default()
            }),
        )
        .unwrap();

    let err = manager
        .validate_token_with_options(
            &token,
            Some(ValidateTokenOptions {
                throw_on_failure: Some(true),
                clock_timestamp: Some(1011.0),
                ..Default::default()
            }),
        )
        .unwrap_err();
    assert!(err.to_string().contains("Token expired"));
}

#[test]
fn native_token_enforces_issuer_and_audience() {
    let mut manager = manager();
    let token = manager
        .generate_token_with_options(
            "payload",
            Some(GenerateTokenOptions {
                issuer: Some("bin-1".into()),
                audience: Some("bin-2".into()),
                issued_at: Some(1000.0),
                ..Default::default()
            }),
        )
        .unwrap();

    let valid = manager
        .validate_token_with_options(
            &token,
            Some(ValidateTokenOptions {
                issuer: Some("bin-1".into()),
                audience: Some("bin-2".into()),
                clock_timestamp: Some(1001.0),
                ..Default::default()
            }),
        )
        .unwrap();
    assert_eq!(valid, Some("payload".to_string()));

    let err = manager
        .validate_token_with_options(
            &token,
            Some(ValidateTokenOptions {
                throw_on_failure: Some(true),
                audience: Some("bin-3".into()),
                clock_timestamp: Some(1001.0),
                ..Default::default()
            }),
        )
        .unwrap_err();
    assert!(err.to_string().contains("audience mismatch"));
}

#[test]
fn manager_generates_and_validates_jwt() {
    let manager = manager();
    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    claims.insert("role".to_string(), "admin".into());

    let token = manager
        .generate_jwt(&claims, Some(ManagerSignJwtOptions::default()))
        .unwrap();

    let verified: JwtClaims = manager
        .validate_jwt::<JwtClaims>(&token, Some(ManagerVerifyJwtOptions::default()))
        .unwrap();

    assert_eq!(verified.get("sub").unwrap(), "user-123");
    assert_eq!(verified.get("role").unwrap(), "admin");
}

#[test]
fn manager_applies_default_jwt_algorithms() {
    let options = AdvancedTokenManagerOptions {
        jwt_default_algorithms: Some(vec![JwtAlgorithm::HS256]),
        ..Default::default()
    };
    let manager = AdvancedTokenManager::new(
        Some("averysecuresecretvalue".to_string()),
        Some(vec!["salt-a".into(), "salt-b".into()]),
        Some(Algorithm::Sha256),
        true,
        true,
        Some(options.clone()),
    )
    .unwrap();

    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    let token = manager.generate_jwt(&claims, None).unwrap();

    let verify_options = ManagerVerifyJwtOptions {
        algorithms: Some(vec![JwtAlgorithm::HS256]),
        ..Default::default()
    };
    manager
        .validate_jwt::<JwtClaims>(&token, Some(verify_options))
        .unwrap();
}

#[test]
fn validate_token_with_options_no_throw() {
    let mut manager = manager();
    let token = manager.generate_token("payload", None).unwrap();
    let tampered = format!("{}x", token);
    let result = manager
        .validate_token_with_options(
            &tampered,
            Some(ValidateTokenOptions {
                throw_on_failure: Some(false),
                ..Default::default()
            }),
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn configure_audience_for_jwt_verification() {
    let manager = manager();
    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    claims.insert("aud".to_string(), "service-a".into());

    let token = manager.generate_jwt(&claims, None).unwrap();

    let verify_options = ManagerVerifyJwtOptions {
        audience: Some(Audience::Single("service-a".into())),
        ..Default::default()
    };
    let validated: JwtClaims = manager.validate_jwt(&token, Some(verify_options)).unwrap();
    assert_eq!(validated.get("sub").unwrap(), "user-123");
}

#[test]
fn manager_validate_jwt_rejects_wrong_secret() {
    let manager = manager();
    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    let token = manager.generate_jwt(&claims, None).unwrap();

    let verify_options = ManagerVerifyJwtOptions {
        secret: Some("different-secret-value".into()),
        ..Default::default()
    };
    let err = manager
        .validate_jwt::<JwtClaims>(&token, Some(verify_options))
        .unwrap_err();
    assert!(err.to_string().contains("invalid signature"));
}

#[test]
fn manager_validate_jwt_enforces_max_payload_size() {
    let options = AdvancedTokenManagerOptions {
        jwt_max_payload_size: Some(32),
        ..Default::default()
    };
    let manager = AdvancedTokenManager::new(
        Some("averysecuresecretvalue".to_string()),
        Some(vec!["salt-a".into(), "salt-b".into()]),
        Some(Algorithm::Sha256),
        true,
        true,
        Some(options),
    )
    .unwrap();

    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    claims.insert("large".to_string(), "x".repeat(128).into());
    let token = manager.generate_jwt(&claims, None).unwrap();

    let err = manager.validate_jwt::<JwtClaims>(&token, None).unwrap_err();
    assert!(err.to_string().contains("maxPayloadSize"));
}

#[test]
fn manager_validate_jwt_rejects_disallowed_algorithm() {
    let manager = manager();
    let mut claims: JwtClaims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());
    let sign_options = ManagerSignJwtOptions {
        algorithm: Some(JwtAlgorithm::HS512),
        ..Default::default()
    };
    let token = manager.generate_jwt(&claims, Some(sign_options)).unwrap();

    let verify_options = ManagerVerifyJwtOptions {
        algorithms: Some(vec![JwtAlgorithm::HS256]),
        ..Default::default()
    };
    let err = manager
        .validate_jwt::<JwtClaims>(&token, Some(verify_options))
        .unwrap_err();
    assert!(err.to_string().contains("is not allowed"));
}
