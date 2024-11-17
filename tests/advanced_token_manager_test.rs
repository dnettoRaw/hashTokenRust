#[cfg(test)]

use hash_token_rust::AdvancedTokenManager;
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn create_token_manager() -> AdvancedTokenManager {
        let secret = Some("my-very-secure-key-12345".to_string());
        let salts = Some(vec![
            "salt-one".to_string(),
            "salt-two".to_string(),
            "salt-three".to_string(),
            "salt-four".to_string(),
            "salt-five".to_string(),
        ]);
        AdvancedTokenManager::new(secret, salts, Some("sha256".to_string()), true, true).unwrap()
    }

    #[test]
    fn generate_token() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let token = manager.generate_token(input, None);
        assert!(!token.is_empty());
    }

    #[test]
    fn validate_valid_token() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let token = manager.generate_token(input, None);
        let validated = manager.validate_token(&token);
        assert_eq!(validated, Some(input.to_string()));
    }

    #[test]
    fn validate_modified_token() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let mut token = manager.generate_token(input, None);
        token.push('x'); // Adiciona um caractere inválido ao final
        let validated = manager.validate_token(&token);
        assert_eq!(validated, None);
    }

    #[test]
    fn performance_generate_token() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let iterations = 1000;

        let start = Instant::now();
        for _ in 0..iterations {
            manager.generate_token(input, None);
        }
        let duration = start.elapsed();
        let avg_time = duration.as_secs_f64() / iterations as f64;
        println!("Average time for generate_token: {:.6} ms", avg_time * 1000.0);
    }

    #[test]
    fn performance_validate_token() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let token = manager.generate_token(input, None);
        let iterations = 1000;

        let start = Instant::now();
        for _ in 0..iterations {
            manager.validate_token(&token);
        }
        let duration = start.elapsed();
        let avg_time = duration.as_secs_f64() / iterations as f64;
        println!("Average time for validate_token: {:.6} ms", avg_time * 1000.0);
    }

    #[test]
    fn unique_tokens_for_same_input() {
        let mut manager = create_token_manager();
        let input = "sensitive-data";
        let token1 = manager.generate_token(input, None);
        let token2 = manager.generate_token(input, None);
        assert_ne!(token1, token2);
    }

    #[test]
    fn invalid_secret_key() {
        let result = AdvancedTokenManager::new(Some("".to_string()), None, Some("sha256".to_string()), false, true);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_salt_array() {
        let result = AdvancedTokenManager::new(
            Some("my-very-secure-key-12345".to_string()),
            Some(vec![]),
            Some("sha256".to_string()),
            false,
            true,
        );
        assert!(result.is_err());
    }
}
