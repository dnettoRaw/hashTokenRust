use hash_token_rust::{
    sign_jwt, verify_jwt, JwtAlgorithm, JwtClaims, SignJwtOptions, VerifyJwtOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = JwtClaims::new();
    claims.insert("sub".to_string(), "user-123".into());

    let token = sign_jwt(
        &claims,
        &SignJwtOptions {
            secret: "a-very-secure-secret-value".to_string(),
            algorithm: Some(JwtAlgorithm::HS256),
            expires_in: Some(300.0),
            ..Default::default()
        },
    )?;

    let verified = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "a-very-secure-secret-value".to_string(),
            algorithms: Some(vec![JwtAlgorithm::HS256]),
            ..Default::default()
        },
    )?;

    println!("subject={}", verified["sub"]);
    Ok(())
}
