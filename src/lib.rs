pub mod advanced_token_manager;
pub mod jwt;

pub use advanced_token_manager::{
    AdvancedTokenError, AdvancedTokenManager, AdvancedTokenManagerLogger,
    AdvancedTokenManagerOptions, Algorithm, ManagerConfig, ManagerSignJwtOptions,
    ManagerVerifyJwtOptions, TokenValidationError, ValidateTokenOptions,
};

pub use jwt::{
    sign_jwt, verify_jwt, verify_jwt_as, Audience, Issuer, JwtAlgorithm, JwtClaims, JwtError,
    SignJwtOptions, VerifyJwtOptions,
};

pub const LIBRARY_VERSION: &str = "0.2.0";

#[cfg(test)]
mod docs {
    use super::*;

    #[test]
    fn example_usage() {
        let mut manager = AdvancedTokenManager::new(
            Some("my-very-secure-key".to_string()),
            Some(vec!["salt1".to_string(), "salt2".to_string()]),
            Some(Algorithm::Sha256),
            true,
            true,
            Some(AdvancedTokenManagerOptions::default()),
        )
        .unwrap();

        let token = manager.generate_token("my-data", None).unwrap();
        let validated = manager.validate_token(&token).unwrap();
        assert_eq!(validated, Some("my-data".to_string()));
    }
}
