use hash_token_rust::{
    AdvancedTokenManager, Algorithm, GenerateTokenOptions, ValidateTokenOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = AdvancedTokenManager::new(
        b"very-secure-secret",
        &[b"salt-a".as_slice(), b"salt-b".as_slice()],
        Algorithm::Sha256,
    )?;

    let token = manager.generate_token(
        "user-id=123",
        GenerateTokenOptions {
            expires_in: Some(300),
            issuer: Some("bin-a"),
            audience: Some("bin-b"),
            ..Default::default()
        },
    )?;

    let verified = manager.validate_token(
        &token,
        ValidateTokenOptions {
            issuer: Some("bin-a"),
            audience: Some("bin-b"),
            ..Default::default()
        },
    )?;

    println!("payload={}", verified.payload);
    println!("salt_index={}", verified.salt_index);

    let sealed = manager.seal_token(
        "email=user@example.com",
        GenerateTokenOptions {
            expires_in: Some(300),
            issuer: Some("bin-a"),
            audience: Some("bin-b"),
            ..Default::default()
        },
    )?;
    let opened = manager.open_token(
        &sealed,
        ValidateTokenOptions {
            issuer: Some("bin-a"),
            audience: Some("bin-b"),
            ..Default::default()
        },
    )?;
    println!("sealed_payload={}", opened.payload);
    Ok(())
}
