#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine as _};
    use hash_token_rust::{advanced_token_manager::Algorithm, AdvancedTokenManager};

    use std::time::Instant;

    fn create_token_manager() -> AdvancedTokenManager {
        let secret = Some("my-very-secure-key-12345".to_string());
        let salts = Some(vec![
            "salt-one".to_string(),
            "salt-two".to_string(),
            "salt-three".to_string(),
            "salt-four".to_string(),
            "salt-five".to_string(),
        ]);
        AdvancedTokenManager::new(secret, salts, Some(Algorithm::Sha256), true, true).unwrap()
    }

    #[test]
    fn generate_token() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token: String = manager.generate_token(input, None);
        assert!(!token.is_empty());
    }

    #[test]
    fn validate_valid_token() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token: String = manager.generate_token(input, None);
        let validated: Option<String> = manager.validate_token(&token);
        assert_eq!(validated, Some(input.to_string()));
    }

    #[test]
    fn validate_modified_token() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let mut token: String = manager.generate_token(input, None);
        token.push('x'); // Modifica o token
        let validated: Option<String> = manager.validate_token(&token);
        assert_eq!(validated, None);
    }

    #[test]
    fn unique_tokens_for_same_input() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token1: String = manager.generate_token(input, None);
        let token2: String = manager.generate_token(input, None);
        assert_ne!(token1, token2); // Tokens devem ser diferentes devido aos salts aleatórios
    }

    #[test]
    fn performance_generate_token() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let iterations: i32 = 1000;

        let start: Instant = Instant::now();
        for _ in 0..iterations {
            manager.generate_token(input, None);
        }
        let duration: std::time::Duration = start.elapsed();
        let avg_time: f64 = duration.as_secs_f64() / iterations as f64;
        println!("Average time for generate_token: {:.6} ms", avg_time * 1000.0);
    }

    #[test]
    fn performance_validate_token() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token: String = manager.generate_token(input, None);
        let iterations: i32 = 1000;

        let start: Instant = Instant::now();
        for _ in 0..iterations {
            manager.validate_token(&token);
        }
        let duration: std::time::Duration = start.elapsed();
        let avg_time: f64 = duration.as_secs_f64() / iterations as f64;
        println!("Average time for validate_token: {:.6} ms", avg_time * 1000.0);
    }

    #[test]
    fn invalid_secret_key() {
        let result: Result<AdvancedTokenManager, String> = AdvancedTokenManager::new(Some("".to_string()), None, Some(Algorithm::Sha256), false, true);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_salt_array() {
        let result: Result<AdvancedTokenManager, String> = AdvancedTokenManager::new(
            Some("my-very-secure-key-12345".to_string()),
            Some(vec![]),
            Some(Algorithm::Sha256),
            false,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn generate_token_with_forced_salt_index() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let forced_salt_index = 2;

        let token: String = manager.generate_token(input, Some(forced_salt_index));

        let decoded_token: Vec<u8> = general_purpose::STANDARD.decode(&token).unwrap();
        let token_str: String = String::from_utf8(decoded_token).unwrap();
        let parts: Vec<&str> = token_str.split('|').collect();

        assert_eq!(parts[1].parse::<usize>().unwrap(), forced_salt_index);
    }

    #[test]
    fn validate_token_with_invalid_salt_index() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token: String = manager.generate_token(input, None);

        let decoded_token: Vec<u8> = general_purpose::STANDARD.decode(&token).unwrap();
        let token_str: String = String::from_utf8(decoded_token).unwrap();
        let mut parts: Vec<&str> = token_str.split('|').collect();

        parts[1] = "100"; // Altera o índice do salt para um inválido
        let tampered_token: String = general_purpose::STANDARD.encode(parts.join("|"));
        assert_eq!(manager.validate_token(&tampered_token), None);
    }

    #[test]
    fn detect_tokens_with_tampered_checksum() {
        let mut manager: AdvancedTokenManager = create_token_manager();
        let input: &str = "sensitive-data";
        let token: String = manager.generate_token(input, None);

        let decoded_token: Vec<u8> = general_purpose::STANDARD.decode(&token).unwrap();
        let token_str: String = String::from_utf8(decoded_token).unwrap();
        let mut parts: Vec<&str> = token_str.split('|').collect();

        parts[2] = "tampered_checksum"; // Modifica o checksum
        let tampered_token: String = general_purpose::STANDARD.encode(parts.join("|"));
        assert_eq!(manager.validate_token(&tampered_token), None);
    }
}
