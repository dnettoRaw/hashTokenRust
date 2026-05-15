use hash_token_rust::{
    AdvancedTokenManager, AdvancedTokenManagerOptions, Algorithm, JwtAlgorithm, JwtClaims,
    ManagerVerifyJwtOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = AdvancedTokenManager::new(
        Some("a-very-secure-secret-value".to_string()),
        Some(vec!["salt-a".into(), "salt-b".into()]),
        Some(Algorithm::Sha256),
        false,
        true,
        Some(AdvancedTokenManagerOptions {
            jwt_default_algorithms: Some(vec![JwtAlgorithm::HS256]),
            jwt_max_payload_size: Some(1024),
            ..Default::default()
        }),
    )?;

    let mut claims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());

    let token = manager.generate_jwt(&claims, None)?;
    let verified: JwtClaims =
        manager.validate_jwt(&token, Some(ManagerVerifyJwtOptions::default()))?;

    println!("subject={}", verified["sub"]);
    Ok(())
}
