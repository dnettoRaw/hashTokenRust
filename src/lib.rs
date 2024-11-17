// Declara o módulo advanced_token_manager
pub mod advanced_token_manager;

// Reexporta o AdvancedTokenManager para facilitar o uso externo
pub use advanced_token_manager::AdvancedTokenManager;

/// # Exemplo de Uso:
/// ```
/// use hash_token_rust::AdvancedTokenManager;
///
/// let mut manager = AdvancedTokenManager::new(
///     Some("secure-key-1234567890".to_string()), // Chave com tamanho suficiente
///     Some(vec!["salt1".to_string(), "salt2".to_string()]),
///     Some("sha256".to_string()),
///     true,
///     true,
/// ).unwrap();
///
/// let token = manager.generate_token("my-data", None);
/// let is_valid = manager.validate_token(&token).is_some();
/// assert!(is_valid);
/// ```

pub const LIBRARY_VERSION: &str = "0.1.0";
