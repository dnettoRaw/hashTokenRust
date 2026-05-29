# hash_token_rust

Tokens natifs signes et scelles, minimaux, pour binaires Rust standalone.

Format principal :

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

`htr1` signe les donnees, mais ne les cache pas. `hte1` chiffre et authentifie le payload avec ChaCha20-Poly1305 en utilisant une cle derivee du secret partage et du salt selectionne.

## Usage

Utilisez ceci quand vos propres binaires doivent echanger des donnees signees sans cles publiques, certificats, services, frameworks ou beaucoup de dependances.

## Securite

- `htr1` signe les donnees ; ne les cache pas.
- `hte1` scelle les donnees ; chiffre et authentifie le payload.
- Utilisez les tokens signes pour l'authenticite et les tokens scelles pour le secret du payload.
- Utilisez un secret fort et des salts rotates volontairement.
- `validate_token` retourne le payload et les metadata valides.
- `validate_payload` existe quand seul le payload est necessaire.
- `generate_token_bytes` et `validate_token_bytes` supportent les payloads non UTF-8.
- `seal_token_bytes` et `open_token_bytes` supportent les payloads chiffres non UTF-8.

## Developpement

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
