# hash_token_rust

Minimal native signed and sealed tokens for standalone Rust binaries.

`hash_token_rust` is for small programs that need to exchange data using shared secrets without pulling in a large authentication stack, public/private key files, certificates, services, frameworks, or JWT as the primary format.

It provides two native token modes:

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

- `htr1` is signed: the payload is readable, but tampering is detected.
- `hte1` is sealed: the payload is encrypted and authenticated.

## Why This Exists

This crate is designed for standalone binaries that belong to the same system and can share a secret plus salts. A typical use case is:

- binary A emits a small payload;
- binary B validates that the payload came from someone who knows the secret;
- tokens can expire;
- tokens can be scoped to an issuer and audience;
- salts can be rotated or selected explicitly;
- no `.pem`, `.pub`, certificate chain, server dependency, or heavy framework is required.

This is not a password hashing library. It is not a replacement for Argon2, bcrypt, or scrypt. It is a compact token manager for authenticating and, when sealed mode is used, encrypting data exchanged between trusted binaries.

## Token Modes

### Signed Tokens: `htr1`

Use signed tokens when the payload is allowed to be readable but must not be modifiable.

The signature authenticates:

- token version;
- encoded payload;
- encoded metadata;
- selected salt;
- shared secret.

Good uses:

- user or job identifiers;
- command payloads that are not secret;
- short-lived handoff tokens;
- internal messages where integrity matters.

### Sealed Tokens: `hte1`

Use sealed tokens when the payload must not be readable by whoever sees the token.

Sealed tokens use `ChaCha20-Poly1305`, an AEAD cipher. The encryption key is derived from the manager secret and the selected salt. Metadata and nonce are authenticated as associated data, so changing them invalidates the token.

Good uses:

- sensitive user data;
- private internal messages;
- payloads that need integrity and confidentiality.

## Installation

```toml
[dependencies]
hash_token_rust = "0.3"
```

If using the repository directly:

```toml
[dependencies]
hash_token_rust = { path = "../hashTokenRust" }
```

## Creating A Manager

```rust
use hash_token_rust::{AdvancedTokenManager, Algorithm};

let mut manager = AdvancedTokenManager::new(
    b"very-secure-secret",
    &[b"salt-a".as_slice(), b"salt-b".as_slice()],
    Algorithm::Sha256,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The manager needs:

| Field | Meaning |
| --- | --- |
| `secret` | Shared secret known by binaries that should trust each other. Must be at least 16 bytes. |
| `salts` | One or more non-empty salts. The selected salt index is stored in metadata. |
| `algorithm` | HMAC algorithm for signed tokens and key derivation. `Sha256` or `Sha512`. |

## Signed Token Example

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

If you only need the payload:

```rust
let payload = manager.validate_payload(
    &token,
    ValidateTokenOptions {
        issuer: Some("bin-a"),
        audience: Some("bin-b"),
        ..Default::default()
    },
)?;

assert_eq!(payload, "user-id=123");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Sealed Token Example

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

## Binary Payloads

Use the byte APIs when the payload is not UTF-8.

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

For encrypted binary payloads:

```rust
let token = manager.seal_token_bytes(
    &[0, 1, 2, 255],
    GenerateTokenOptions::default(),
)?;

let verified = manager.open_token_bytes(
    &token,
    ValidateTokenOptions::default(),
)?;

assert_eq!(verified.payload, vec![0, 1, 2, 255]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Options

### `GenerateTokenOptions`

| Option | Meaning |
| --- | --- |
| `salt_index` | Selects a specific salt. If absent, a random salt index is used. |
| `expires_in` | Adds an expiration time in seconds from `issued_at`. |
| `issuer` | Identifies who created the token. |
| `audience` | Identifies who should accept the token. |
| `issued_at` | Overrides the issue timestamp. Useful for tests. |

### `ValidateTokenOptions`

| Option | Meaning |
| --- | --- |
| `max_age` | Rejects tokens older than this many seconds based on `issued_at`. |
| `issuer` | Requires the token issuer to match. |
| `audience` | Requires the token audience to match. |
| `clock_tolerance` | Allows small clock drift in seconds. |
| `clock_timestamp` | Overrides current time. Useful for tests. |

## Verified Output

`validate_token` and `open_token` return `VerifiedToken`:

```rust
pub struct VerifiedToken {
    pub payload: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub salt_index: usize,
    pub algorithm: String,
}
```

The byte APIs return `VerifiedBytes`, which has the same metadata and a `Vec<u8>` payload.

## Salt Rotation

Tokens store the selected salt index in metadata. This makes rotation straightforward:

- keep old salts available while older tokens may still be valid;
- generate new tokens with the new salt index;
- remove old salts only after all old tokens have expired.

If binaries do not share the same secret and salt list, validation or opening fails.

## Security Notes

- `htr1` signs data; it does not hide data.
- `hte1` seals data; it encrypts and authenticates the payload.
- Signed tokens are for authenticity and integrity.
- Sealed tokens are for authenticity, integrity and payload secrecy.
- Use high-entropy shared secrets.
- Rotate salts deliberately.
- Keep token lifetimes short when tokens cross process or machine boundaries.
- Do not use this as password hashing.
- If a shared secret leaks, tokens for that trust group should be considered compromised.

## Examples

```bash
cargo run --example native_signed
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## Design Goals

- Rust 2021.
- Small files and short functions.
- Clear `Result<T, TokenError>` errors.
- Minimal dependencies.
- No framework.
- No JWT dependency.
- No panic in library code for normal error paths.
- Avoid unnecessary allocation where the code can stay clear.
