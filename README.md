# hash_token_rust

Minimal native signed and sealed tokens for standalone Rust binaries.

The main format is:

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

`htr1` signs data but does not hide it. `hte1` encrypts and authenticates data with ChaCha20-Poly1305 using a key derived from the shared secret and selected salt.

## Use Case

Use this when your own binaries need to exchange signed data without public keys, certificates, services, frameworks, or a large dependency tree.

## Example

```rust
use hash_token_rust::{
    AdvancedTokenManager, Algorithm, GenerateTokenOptions, ValidateTokenOptions,
};

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

assert_eq!(verified.payload, "user-id=123");
assert_eq!(verified.issuer.as_deref(), Some("bin-a"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Sealed Payloads

Use sealed tokens when the payload must not be readable by whoever sees the token.

```rust
let token = manager.seal_token(
    "email=user@example.com",
    GenerateTokenOptions {
        expires_in: Some(300),
        issuer: Some("bin-a"),
        audience: Some("bin-b"),
        ..Default::default()
    },
)?;

let verified = manager.open_token(
    &token,
    ValidateTokenOptions {
        issuer: Some("bin-a"),
        audience: Some("bin-b"),
        ..Default::default()
    },
)?;

assert_eq!(verified.payload, "email=user@example.com");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Security Notes

- `htr1` signs data; it does not hide data.
- `hte1` seals data; it encrypts and authenticates the payload.
- Use signed tokens for authenticity and sealed tokens for payload secrecy.
- Use a strong shared secret and rotate salts deliberately.
- `validate_token` returns validated metadata with the payload.
- `validate_payload` is available when only the payload is needed.
- `generate_token_bytes` and `validate_token_bytes` support non-UTF-8 payloads.
- `seal_token_bytes` and `open_token_bytes` support encrypted non-UTF-8 payloads.

## Binary Payloads

```rust
let token = manager.generate_token_bytes(
    &[0, 1, 2, 255],
    GenerateTokenOptions::default(),
)?;

let verified = manager.validate_token_bytes(
    &token,
    ValidateTokenOptions::default(),
)?;

assert_eq!(verified.payload, vec![0, 1, 2, 255]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
