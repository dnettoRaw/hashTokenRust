# hash_token_rust

Tokens natifs signes et minimaux pour binaires Rust standalone.

Format principal :

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
```

Le payload est encode, pas chiffre. La signature authentifie le token avec HMAC en utilisant un secret partage et le salt selectionne.

## Usage

Utilisez ceci quand vos propres binaires doivent echanger des donnees signees sans cles publiques, certificats, services, frameworks ou beaucoup de dependances.

## Securite

- Signe les donnees ; ne cache pas les donnees.
- Sert pour authenticite, integrite, age, issuer et audience.
- Utilisez un secret fort et des salts rotates volontairement.
- `validate_token` retourne le payload et les metadata valides.
- `validate_payload` existe quand seul le payload est necessaire.
- `generate_token_bytes` et `validate_token_bytes` supportent les payloads non UTF-8.
- Si le secret du payload est requis, ajoutez un mode chiffre separe.

## Developpement

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
