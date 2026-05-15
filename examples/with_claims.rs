use hash_token_rust::{
    sign_jwt, verify_jwt, Audience, Issuer, JwtAlgorithm, JwtClaims, SignJwtOptions,
    VerifyJwtOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = JwtClaims::new();
    claims.insert("role".to_string(), "admin".into());

    let token = sign_jwt(
        &claims,
        &SignJwtOptions {
            secret: "a-very-secure-secret-value".to_string(),
            algorithm: Some(JwtAlgorithm::HS512),
            expires_in: Some(600.0),
            audience: Some(Audience::Single("internal-api".into())),
            issuer: Some("auth-service".into()),
            subject: Some("user-123".into()),
            ..Default::default()
        },
    )?;

    let verified = verify_jwt(
        &token,
        &VerifyJwtOptions {
            secret: "a-very-secure-secret-value".to_string(),
            algorithms: Some(vec![JwtAlgorithm::HS512]),
            audience: Some(Audience::Single("internal-api".into())),
            issuer: Some(Issuer::Single("auth-service".into())),
            subject: Some("user-123".into()),
            ..Default::default()
        },
    )?;

    println!("claims={verified:?}");
    Ok(())
}
