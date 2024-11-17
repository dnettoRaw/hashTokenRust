// Declara o módulo advanced_token_manager
pub mod advanced_token_manager;

// Reexporta o AdvancedTokenManager para facilitar o uso externo
pub use advanced_token_manager::{AdvancedTokenManager, Algorithm};


/// # Exemplo de Uso:
/// ```
/// use hash_token_rust::{AdvancedTokenManager, Algorithm};
///
/// let mut manager = AdvancedTokenManager::new(
///     Some("my-very-secure-key".to_string()), // Segredo com mais de 16 caracteres
///     Some(vec!["salt1".to_string(), "salt2".to_string()]),
///     Some(Algorithm::Sha256), // Algoritmo especificado corretamente
///     true,
///     true
/// ).unwrap();
///
/// let token = manager.generate_token("my-data", None);
/// let is_valid = manager.validate_token(&token).is_some();
/// assert!(is_valid);
/// ```



pub const LIBRARY_VERSION: &str = "0.1.0";
