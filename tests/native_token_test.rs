use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hash_token_rust::{
    AdvancedTokenManager, Algorithm, GenerateTokenOptions, TokenError, ValidateTokenOptions,
};

fn manager() -> AdvancedTokenManager {
    AdvancedTokenManager::new(
        b"very-secure-secret",
        &[b"salt-a".as_slice(), b"salt-b".as_slice()],
        Algorithm::Sha256,
    )
    .unwrap()
}

#[test]
fn signs_and_validates_payload() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "user-id=123",
            GenerateTokenOptions {
                issued_at: Some(1000),
                salt_index: Some(0),
                ..Default::default()
            },
        )
        .unwrap();

    let verified = manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1001),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(verified.payload, "user-id=123");
    assert_eq!(verified.issued_at, 1000);
    assert_eq!(verified.salt_index, 0);
}

#[test]
fn token_has_native_shape_and_salt_index() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                salt_index: Some(1),
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts[0], "htr1");

    let meta = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    assert!(meta.contains("HS256|1|1000|"));
}

#[test]
fn rejects_tampered_payload() {
    let mut manager = manager();
    let token = manager
        .generate_token("payload", GenerateTokenOptions::default())
        .unwrap();
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[1] = "dGFtcGVyZWQ";
    let tampered = parts.join(".");

    let err = manager
        .validate_token(&tampered, ValidateTokenOptions::default())
        .unwrap_err();
    assert!(err.to_string().contains("signature"));
}

#[test]
fn enforces_expiration_and_max_age() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                expires_in: Some(10),
                ..Default::default()
            },
        )
        .unwrap();

    let expired = manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1011),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(expired.to_string().contains("expired"));

    let too_old = manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1006),
                max_age: Some(5),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(too_old.to_string().contains("maxAge"));
}

#[test]
fn enforces_issuer_and_audience() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issuer: Some("bin-a"),
                audience: Some("bin-b"),
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();

    manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                issuer: Some("bin-a"),
                audience: Some("bin-b"),
                clock_timestamp: Some(1001),
                ..Default::default()
            },
        )
        .unwrap();

    let err = manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                audience: Some("bin-c"),
                clock_timestamp: Some(1001),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("audience mismatch"));
}

#[test]
fn validates_payload_helper() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    let payload = manager
        .validate_payload(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(payload, "payload");
}

#[test]
fn signs_and_validates_binary_payload() {
    let mut manager = manager();
    let bytes = [0, 159, 146, 150, 255];
    let token = manager
        .generate_token_bytes(
            &bytes,
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();

    let verified = manager
        .validate_token_bytes(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1001),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(verified.payload, bytes);

    let err = manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1001),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(err.to_string().contains("UTF-8"));
}

#[test]
fn seals_and_opens_text_payload() {
    let mut manager = manager();
    let token = manager
        .seal_token(
            "email=user@example.com",
            GenerateTokenOptions {
                issued_at: Some(1000),
                issuer: Some("bin-a"),
                audience: Some("bin-b"),
                ..Default::default()
            },
        )
        .unwrap();

    assert!(token.starts_with("hte1."));
    assert!(!token.contains("user@example.com"));

    let verified = manager
        .open_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1001),
                issuer: Some("bin-a"),
                audience: Some("bin-b"),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(verified.payload, "email=user@example.com");
}

#[test]
fn seals_and_opens_binary_payload() {
    let mut manager = manager();
    let bytes = [0, 1, 2, 3, 255];
    let token = manager
        .seal_token_bytes(
            &bytes,
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();

    let verified = manager
        .open_token_bytes(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(verified.payload, bytes);
}

#[test]
fn sealed_token_rejects_wrong_secret_and_tampering() {
    let mut manager = manager();
    let token = manager
        .seal_token(
            "secret-data",
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();

    let other = AdvancedTokenManager::new(
        b"other-secure-secret",
        &[b"salt-a".as_slice(), b"salt-b".as_slice()],
        Algorithm::Sha256,
    )
    .unwrap();
    assert!(other
        .open_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string()
        .contains("open"));

    let mut parts: Vec<&str> = token.split('.').collect();
    parts[1] = "dGFtcGVyZWQ";
    assert!(manager
        .open_token(&parts.join("."), ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("open"));
}

#[test]
fn rejects_bad_structure_and_base64() {
    let manager = manager();

    assert!(manager
        .validate_token("htr1.a.b.c.extra", ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("structure"));
    assert!(manager
        .validate_token("htr1..b.c", ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("structure"));
    assert!(manager
        .validate_token("htr1.abc=.b.c", ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("payload"));
}

#[test]
fn rejects_invalid_metadata() {
    let manager = manager();
    let payload = URL_SAFE_NO_PAD.encode("payload");
    let bad_meta = URL_SAFE_NO_PAD.encode("HS256|0|1000");
    let token = format!("htr1.{}.{}.c2ln", payload, bad_meta);

    assert!(manager
        .validate_token(&token, ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("metadata"));
}

#[test]
fn rejects_wrong_secret_and_salt() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                salt_index: Some(1),
                ..Default::default()
            },
        )
        .unwrap();

    let other_secret = AdvancedTokenManager::new(
        b"other-secure-secret",
        &[b"salt-a".as_slice(), b"salt-b".as_slice()],
        Algorithm::Sha256,
    )
    .unwrap();
    assert!(other_secret
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string()
        .contains("signature"));

    let missing_salt = AdvancedTokenManager::new(
        b"very-secure-secret",
        &[b"salt-a".as_slice()],
        Algorithm::Sha256,
    )
    .unwrap();
    assert!(missing_salt
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string()
        .contains("salt"));
}

#[test]
fn rejects_tampered_metadata_and_signature() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();
    let mut parts: Vec<&str> = token.split('.').collect();
    let meta = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    let changed = meta.replacen("HS256", "HS512", 1);
    let encoded_changed = URL_SAFE_NO_PAD.encode(changed);
    parts[2] = &encoded_changed;
    let tampered_meta = parts.join(".");

    assert!(manager
        .validate_token(
            &tampered_meta,
            ValidateTokenOptions {
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string()
        .contains("Algorithm"));

    let truncated = token.rsplit_once('.').unwrap().0.to_string() + ".abc";
    assert!(manager
        .validate_token(&truncated, ValidateTokenOptions::default())
        .unwrap_err()
        .to_string()
        .contains("signature"));
}

#[test]
fn rejects_missing_scope_when_required() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                ..Default::default()
            },
        )
        .unwrap();

    assert!(manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                issuer: Some("bin-a"),
                clock_timestamp: Some(1000),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string()
        .contains("Missing issuer"));
}

#[test]
fn clock_tolerance_allows_expiration_drift() {
    let mut manager = manager();
    let token = manager
        .generate_token(
            "payload",
            GenerateTokenOptions {
                issued_at: Some(1000),
                expires_in: Some(10),
                ..Default::default()
            },
        )
        .unwrap();

    manager
        .validate_token(
            &token,
            ValidateTokenOptions {
                clock_timestamp: Some(1012),
                clock_tolerance: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
}

#[test]
fn rejects_short_secret() {
    let err: TokenError =
        match AdvancedTokenManager::new(b"short", &[b"salt".as_slice()], Algorithm::Sha256) {
            Ok(_) => panic!("short secret should be rejected"),
            Err(error) => error,
        };
    assert!(err.to_string().contains("Secret"));
}
