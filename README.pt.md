# hash_token_rust

Tokens nativos assinados e selados, mínimos, para binários Rust standalone.

`hash_token_rust` é para programas pequenos que precisam trocar dados usando segredos compartilhados sem trazer uma pilha grande de autenticação, arquivos de chave pública/privada, certificados, serviços, frameworks ou JWT como formato principal.

Ele oferece dois modos nativos de token:

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

- `htr1` é assinado: o payload é legível, mas alterações são detectadas.
- `hte1` é selado: o payload é criptografado e autenticado.

## Por Que Isto Existe

Este crate foi desenhado para binários standalone que pertencem ao mesmo sistema e podem compartilhar um segredo mais salts. Um caso típico:

- binário A emite um payload pequeno;
- binário B valida que o payload veio de alguém que conhece o segredo;
- tokens podem expirar;
- tokens podem ser limitados por issuer e audience;
- salts podem ser rotacionados ou selecionados explicitamente;
- não é necessário `.pem`, `.pub`, cadeia de certificados, serviço central ou framework pesado.

Isto não é uma biblioteca de hash de senha. Não substitui Argon2, bcrypt ou scrypt. É um gerenciador compacto de tokens para autenticar e, no modo selado, criptografar dados trocados entre binários confiáveis.

## Modos De Token

### Tokens Assinados: `htr1`

Use tokens assinados quando o payload pode ser legível, mas não pode ser modificado.

A assinatura autentica:

- versão do token;
- payload codificado;
- metadata codificado;
- salt selecionado;
- segredo compartilhado.

Bons usos:

- identificadores de usuário ou job;
- comandos que não são secretos;
- tokens curtos de passagem entre processos;
- mensagens internas onde integridade importa.

### Tokens Selados: `hte1`

Use tokens selados quando o payload não deve ser legível por quem vê o token.

Tokens selados usam `ChaCha20-Poly1305`, uma cifra AEAD. A chave de criptografia é derivada do segredo do manager e do salt selecionado. Metadata e nonce são autenticados como dados associados, então alterá-los invalida o token.

Bons usos:

- dados sensíveis de usuário;
- mensagens internas privadas;
- payloads que precisam de integridade e confidencialidade.

## Instalação

```toml
[dependencies]
hash_token_rust = "0.3"
```

Usando o repositório diretamente:

```toml
[dependencies]
hash_token_rust = { path = "../hashTokenRust" }
```

## Criando Um Manager

```rust
use hash_token_rust::{AdvancedTokenManager, Algorithm};

let mut manager = AdvancedTokenManager::new(
    b"very-secure-secret",
    &[b"salt-a".as_slice(), b"salt-b".as_slice()],
    Algorithm::Sha256,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

O manager precisa de:

| Campo | Significado |
| --- | --- |
| `secret` | Segredo compartilhado pelos binários que devem confiar entre si. Deve ter pelo menos 16 bytes. |
| `salts` | Um ou mais salts não vazios. O índice do salt selecionado fica no metadata. |
| `algorithm` | Algoritmo HMAC para tokens assinados e derivação de chave. `Sha256` ou `Sha512`. |

## Exemplo De Token Assinado

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

Quando você precisa apenas do payload:

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

## Exemplo De Token Selado

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

## Payloads Binários

Use as APIs de bytes quando o payload não é UTF-8.

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

Para payloads binários criptografados:

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

## Opções

### `GenerateTokenOptions`

| Opção | Significado |
| --- | --- |
| `salt_index` | Seleciona um salt específico. Se ausente, um índice aleatório é usado. |
| `expires_in` | Adiciona expiração em segundos a partir de `issued_at`. |
| `issuer` | Identifica quem criou o token. |
| `audience` | Identifica quem deve aceitar o token. |
| `issued_at` | Sobrescreve o timestamp de emissão. Útil para testes. |

### `ValidateTokenOptions`

| Opção | Significado |
| --- | --- |
| `max_age` | Rejeita tokens mais antigos que este número de segundos com base em `issued_at`. |
| `issuer` | Exige que o issuer do token seja igual. |
| `audience` | Exige que a audience do token seja igual. |
| `clock_tolerance` | Permite pequena diferença de relógio em segundos. |
| `clock_timestamp` | Sobrescreve o horário atual. Útil para testes. |

## Saída Validada

`validate_token` e `open_token` retornam `VerifiedToken`:

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

As APIs de bytes retornam `VerifiedBytes`, com o mesmo metadata e payload `Vec<u8>`.

## Rotação De Salts

Tokens armazenam o índice do salt selecionado no metadata. Isso deixa a rotação simples:

- mantenha salts antigos disponíveis enquanto tokens antigos ainda podem ser válidos;
- gere novos tokens com o novo índice de salt;
- remova salts antigos apenas depois que todos os tokens antigos expirarem.

Se os binários não compartilham o mesmo segredo e a mesma lista de salts, a validação ou abertura falha.

## Notas De Segurança

- `htr1` assina dados; não esconde dados.
- `hte1` sela dados; criptografa e autentica o payload.
- Tokens assinados servem para autenticidade e integridade.
- Tokens selados servem para autenticidade, integridade e sigilo do payload.
- Use segredos compartilhados com alta entropia.
- Rotacione salts deliberadamente.
- Use tempos de vida curtos quando tokens atravessam processos ou máquinas.
- Não use isto como hash de senha.
- Se um segredo compartilhado vazar, os tokens desse grupo de confiança devem ser considerados comprometidos.

## Exemplos

```bash
cargo run --example native_signed
```

## Desenvolvimento

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## Metas De Design

- Rust 2021.
- Arquivos pequenos e funções curtas.
- Erros claros com `Result<T, TokenError>`.
- Dependências mínimas.
- Sem framework.
- Sem dependência de JWT.
- Sem panic em código de biblioteca para erros normais.
- Evitar alocação desnecessária quando o código pode continuar claro.
