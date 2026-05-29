# hash_token_rust

Tokens nativos assinados e selados, mínimos, para binários Rust standalone.

Formato principal:

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

`htr1` assina dados, mas nao esconde. `hte1` criptografa e autentica o payload com ChaCha20-Poly1305 usando chave derivada do segredo compartilhado e do salt selecionado.

## Uso

Use quando seus próprios binários precisam trocar dados assinados sem chaves públicas, certificados, serviços, frameworks ou muitas dependências.

## Segurança

- `htr1` assina dados; nao esconde dados.
- `hte1` sela dados; criptografa e autentica o payload.
- Use tokens assinados para autenticidade e tokens selados para sigilo do payload.
- Use segredo forte e salts rotacionados com intenção.
- `validate_token` retorna payload e metadata validados.
- `validate_payload` existe quando só o payload importa.
- `generate_token_bytes` e `validate_token_bytes` suportam payloads que nao sao UTF-8.
- `seal_token_bytes` e `open_token_bytes` suportam payloads criptografados que nao sao UTF-8.

## Desenvolvimento

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
