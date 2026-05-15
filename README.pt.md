# hash_token_rust

Gerenciador leve de tokens em Rust para binarios standalone, segredos compartilhados, salts, controle de idade e suporte JWT opcional.

Documentacao:

- English: `README.md`
- Portugues: `README.pt.md`
- Francais: `README.fr.md`

## Para Que Serve

`hash_token_rust` serve para criar e validar tokens assinados de forma simples, previsivel e facil de auditar.

Ele cobre dois usos principais:

- Tokens HMAC com segredo e salts, gerenciados por `AdvancedTokenManager`.
- JWTs nativos assinados com HMAC usando `HS256` ou `HS512`.

Use este projeto quando programas standalone precisam trocar dados assinados sem certificados, chaves publicas, chaves privadas, frameworks ou muitas dependencias.

## Como Funciona

No fluxo nativo do `AdvancedTokenManager`, o manager guarda um segredo compartilhado e uma lista de salts. Ele gera um formato novo e versionado: `htr1.<payload>.<metadata>.<signature>`. O payload e o metadata usam Base64URL. O metadata carrega versao, algoritmo, indice de salt, `iat`, `exp` opcional, `iss` opcional e `aud` opcional. A assinatura autentica versao, payload e metadata com HMAC mais o salt escolhido.

No fluxo JWT, a biblioteca monta um header JSON e um payload JSON, codifica os dois com Base64URL sem padding, assina o texto `header.payload` com HMAC e grava a assinatura no terceiro segmento. Na validacao, ela valida a estrutura, decodifica os segmentos, verifica o algoritmo, checa a assinatura e depois valida as claims configuradas.

## Exemplo JWT Basico

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

`AdvancedTokenManager` e a API principal. Ele cria tokens nativos `htr1` para comunicacao entre binarios e tambem integra JWT por meio de `generate_jwt` e `validate_jwt`. Por padrao, os JWTs usam o segredo do manager, mas cada chamada pode receber um segredo proprio.

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

## Opcoes Importantes De JWT

| Opcao | Funcao |
| --- | --- |
| `algorithm` | Define o algoritmo de assinatura. O padrao e `HS256`. |
| `algorithms` | Restringe a verificacao aos algoritmos esperados. |
| `expires_in` | Adiciona `exp` relativo ao momento da assinatura. |
| `not_before` | Adiciona `nbf` relativo ao momento da assinatura. |
| `issued_at` | Define `iat`; se ausente, a biblioteca adiciona o timestamp atual. |
| `clock_tolerance` | Permite pequena diferenca de relogio na validacao temporal. |
| `max_age` | Rejeita tokens cujo `iat` seja antigo demais. |
| `audience` | Exige e valida `aud`. |
| `issuer` | Exige e valida `iss`. |
| `subject` | Exige e valida `sub`. |
| `max_payload_size` | Rejeita payloads JWT grandes antes e depois do decode. |
| `allowed_claims` | Restringe claims customizadas fora das claims padrao. |

## Modelo De Seguranca

- `alg: none` e rejeitado.
- Apenas `HS256` e `HS512` exatos sao aceitos.
- Base64URL deve ser canonico e sem padding.
- Segmentos vazios, JSON invalido e claims com tipo invalido sao rejeitados.
- Assinaturas JWT e assinaturas nativas do manager sao comparados sem early exit para entradas de mesmo tamanho.
- Aritmetica temporal usa operacoes checked.
- `exp`, `nbf`, `iat`, `iss`, `aud` e `sub` sao validados quando existem e obrigatorios quando configurados.

Use segredos fortes, limite os algoritmos aceitos na verificacao e configure `max_payload_size` em endpoints publicos.

## Exemplos

```bash
cargo run --example sign_verify
cargo run --example with_claims
cargo run --example manager_integration
```

## Desenvolvimento

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

O codigo e separado por responsabilidade: Base64URL, claims, assinatura, verificacao, tempo, inicializacao do manager, parsing de token e integracao JWT do manager.
