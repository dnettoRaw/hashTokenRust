# hash_token_rust

Lightweight Rust token manager for standalone binaries, shared secrets, salts, token age control and optional JWT support.

Documentation:

- English: `README.md`
- Portugues: `README.pt.md`
- Francais: `README.fr.md`

## What This Library Is For

`hash_token_rust` helps applications create and verify two kinds of tokens:

- Salted HMAC tokens managed by `AdvancedTokenManager`.
- Native JWT tokens signed with HMAC algorithms `HS256` or `HS512`.

The project is intentionally small. It avoids framework-style abstractions and keeps validation, parsing, signing and verification in explicit modules so the security flow is easy to audit.

Use it when standalone programs need to exchange signed data without certificates, public keys, private keys, frameworks or a large dependency tree.

## How It Works

For native manager tokens, the manager stores a shared secret and a list of salts. It emits a new versioned format: `htr1.<payload>.<metadata>.<signature>`. The payload and metadata are Base64URL encoded. Metadata carries the token version, algorithm, salt index, `iat`, optional `exp`, optional `iss` and optional `aud`. The signature authenticates the version, payload and metadata with HMAC plus the selected salt.

For JWTs, the library builds a JSON header and payload, Base64URL-encodes both segments, signs `header.payload` with HMAC, and verifies the signature before validating claims. It rejects unsigned tokens and accepts only exact `HS256` or `HS512`.

## Basic JWT Example

```rust
use hash_token_rust::{
    sign_jwt, verify_jwt, JwtAlgorithm, JwtClaims, SignJwtOptions, VerifyJwtOptions,
};

let mut claims = JwtClaims::new();
claims.insert("sub".to_string(), "user-123".into());

let token = sign_jwt(&claims, &SignJwtOptions {
    secret: "a-very-secure-secret-value".to_string(),
    algorithm: Some(JwtAlgorithm::HS256),
    expires_in: Some(300.0),
    ..Default::default()
})?;

let verified = verify_jwt(&token, &VerifyJwtOptions {
    secret: "a-very-secure-secret-value".to_string(),
    algorithms: Some(vec![JwtAlgorithm::HS256]),
    ..Default::default()
})?;

assert_eq!(verified.get("sub").unwrap(), "user-123");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## AdvancedTokenManager

`AdvancedTokenManager` is the primary API. It creates native `htr1` tokens for binary-to-binary communication and also exposes `generate_jwt` and `validate_jwt`. JWT calls use the manager secret by default, but each call can override the secret when needed.

```rust
use hash_token_rust::{AdvancedTokenManager, AdvancedTokenManagerOptions, Algorithm};

let mut manager = AdvancedTokenManager::new(
    Some("a-very-secure-secret-value".to_string()),
    Some(vec!["salt-a".into(), "salt-b".into()]),
    Some(Algorithm::Sha256),
    false,
    true,
    Some(AdvancedTokenManagerOptions::default()),
)?;

let token = manager.generate_token("payload-data", None)?;
let data = manager.validate_token(&token)?;

assert_eq!(data, Some("payload-data".to_string()));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Important JWT Options

| Option | Purpose |
| --- | --- |
| `algorithm` | Selects the signing algorithm, defaulting to `HS256`. |
| `algorithms` | Restricts verification to expected algorithms. |
| `expires_in` | Adds an `exp` claim relative to the signing timestamp. |
| `not_before` | Adds an `nbf` claim relative to the signing timestamp. |
| `issued_at` | Sets `iat`; otherwise the library adds the current timestamp. |
| `clock_tolerance` | Allows small clock drift during temporal validation. |
| `max_age` | Rejects tokens whose `iat` is older than the configured age. |
| `audience` | Requires and validates `aud`. |
| `issuer` | Requires and validates `iss`. |
| `subject` | Requires and validates `sub`. |
| `max_payload_size` | Rejects large JWT payloads before and after decoding. |
| `allowed_claims` | Restricts non-standard custom claims. |

## Security Model

- `alg: none` is rejected.
- Only exact `HS256` and `HS512` are accepted.
- Base64URL input must be canonical and unpadded.
- Empty segments, malformed JSON and invalid claim shapes are rejected.
- JWT signatures and native manager signatures are compared without early exit for equal-length inputs.
- Temporal arithmetic uses checked operations.
- `exp`, `nbf`, `iat`, `iss`, `aud` and `sub` are validated when present, and required when configured.

Use high-entropy secrets and pin accepted algorithms during verification. For public endpoints, set `max_payload_size`.

## Examples

```bash
cargo run --example sign_verify
cargo run --example with_claims
cargo run --example manager_integration
```

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

The code is split by responsibility: Base64URL, claims, signing, verification, time handling, manager initialization, token parsing and manager JWT integration.
