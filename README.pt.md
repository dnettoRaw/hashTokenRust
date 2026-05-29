# hash_token_rust

Tokens nativos assinados e mínimos para binários Rust standalone.

Formato principal:

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
```

O payload é codificado, não criptografado. A assinatura autentica o token com HMAC usando um segredo compartilhado e o salt selecionado.

## Uso

Use quando seus próprios binários precisam trocar dados assinados sem chaves públicas, certificados, serviços, frameworks ou muitas dependências.

## Segurança

- Assina dados; não esconde dados.
- Serve para autenticidade, integridade, idade, issuer e audience.
- Use segredo forte e salts rotacionados com intenção.
- `validate_token` retorna payload e metadata validados.
- `validate_payload` existe quando só o payload importa.
- `generate_token_bytes` e `validate_token_bytes` suportam payloads que nao sao UTF-8.
- Se precisar de sigilo do payload, adicione um modo criptografado separado.

## Desenvolvimento

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```
