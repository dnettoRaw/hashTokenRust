use base64::Engine;
use hash_token_rust::advanced_token_manager::{
    AdvancedTokenManager, AdvancedTokenManagerOptions, Algorithm, ManagerSignJwtOptions,
    ManagerVerifyJwtOptions, ValidateTokenOptions,
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
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .unwrap();
    let text = String::from_utf8(decoded).unwrap();
    let parts: Vec<&str> = text.split('|').collect();
    assert_eq!(parts[1], "1");
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
    let mut options = AdvancedTokenManagerOptions::default();
    options.jwt_default_algorithms = Some(vec![JwtAlgorithm::HS256]);
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

    let mut verify_options = ManagerVerifyJwtOptions::default();
    verify_options.algorithms = Some(vec![JwtAlgorithm::HS256]);
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

    let mut verify_options = ManagerVerifyJwtOptions::default();
    verify_options.audience = Some(Audience::Single("service-a".into()));
    let validated: JwtClaims = manager.validate_jwt(&token, Some(verify_options)).unwrap();
    assert_eq!(validated.get("sub").unwrap(), "user-123");
}
