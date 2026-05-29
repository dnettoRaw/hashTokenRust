# hashTokenRust — Agents

## Objetivo Do Projeto

Implementar em Rust o mesmo objetivo do `hash-token`: um gerenciador leve de tokens HMAC com suporte JWT nativo, seguro, legivel e sem excesso de abstracao.

O codigo deve ser pequeno, previsivel e facil de auditar. Prefira funcoes curtas, tipos explicitos e fluxo claro.

## Regras Globais De Engenharia

- Linguagem: Rust 2021.
- Validacao obrigatoria antes de assinar, verificar ou decodificar dados externos.
- Evitar dependencias novas. Se uma dependencia for realmente necessaria, justificar no PR/commit.
- Preferir `Result<T, E>` com erros claros em vez de `panic!`.
- Nao usar `unwrap()` ou `expect()` em codigo de biblioteca, exceto em testes quando deixar a intencao mais clara.
- Manter compatibilidade com `cargo test`, `cargo fmt` e `cargo clippy`.
- O codigo deve ser extremamente leve: sem macros complexas, sem frameworks e sem alocacoes desnecessarias.
- Quando houver fluxo com muitos passos, usar state machine simples e explicita.

## Estilo De Arquivos E Funcoes

- Maximo de 5 funcoes por arquivo sempre que for pratico.
- Cada funcao deve fazer quase uma unica tarefa.
- Uma funcao deve ser facil de ler do inicio ao fim sem pular contexto.
- Se um arquivo passar de 5 funcoes, dividir por responsabilidade:
  - parsing
  - assinatura
  - validacao
  - claims
  - erros
  - state machine
- Comentarios sao bem-vindos quando explicam uma decisao de seguranca ou uma etapa nao obvia.
- Evitar comentarios obvios como "incrementa contador".
- Nomes devem descrever a acao: `decode_segment`, `verify_signature`, `validate_expiration`.

## State Machine

Quando possivel, representar validacoes em etapas de state machine. Exemplo:

```rust
enum JwtVerifyState {
    SplitToken,
    DecodeHeader,
    DecodePayload,
    VerifyAlgorithm,
    VerifySignature,
    ValidateClaims,
    Done,
}
```

Regras:

- Cada estado deve ter uma responsabilidade clara.
- Transicoes devem ser explicitas.
- Estados nao devem esconder validacoes criticas.
- Nao criar state machine se isso deixar uma funcao simples mais dificil de entender.

## 1. Refactor Agent

**Papel:** Engenheiro Rust  
**Objetivo:** Manter e evoluir o token manager e o JWT nativo com API publica simples.

Tarefas:

- Implementar assinatura e verificacao JWT HS256/HS512.
- Manter Base64URL encode/decode sem aceitar entrada malformada.
- Integrar `generate_jwt` e `validate_jwt` em `AdvancedTokenManager`.
- Separar responsabilidades em arquivos pequenos.
- Manter tipagem forte e erros legiveis.
- Preferir structs de options em vez de parametros soltos demais.

Checklist:

- `cargo fmt`
- `cargo clippy --all-targets --all-features`
- `cargo test`

## 2. Security Agent

**Papel:** Auditor de seguranca Rust  
**Objetivo:** Revisar o modulo JWT e o manager para evitar falhas comuns.

Checklist:

- Proibir `alg: none`.
- Aceitar apenas HS256 e HS512.
- Comparar assinaturas com igualdade em tempo constante.
- Validar rigorosamente `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`.
- Aplicar `clock_tolerance` de forma segura.
- Rejeitar payloads grandes quando `max_payload_size` estiver definido.
- Rejeitar tokens truncados, segmentos vazios e Base64URL invalido.
- Nao adicionar dependencias externas sem justificativa.
- Manter ou atualizar `SECURITY_NOTES.md` quando houver mudanca de seguranca.

## 3. Test Agent

**Papel:** Engenheiro de testes Rust  
**Objetivo:** Garantir cobertura forte do comportamento critico.

Tarefas:

- Criar ou manter testes em `tests/jwt_test.rs`.
- Criar ou manter testes em `tests/advanced_token_manager_test.rs`.
- Testar sucesso e falhas:
  - HS256
  - HS512
  - expiracao
  - `nbf`
  - `iat` futuro
  - `alg: none`
  - algoritmo inesperado
  - assinatura truncada
  - claims invalidas
  - payload grande
  - segredo errado
- Testar integracao com `AdvancedTokenManager`.

Comandos:

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features
```

## 4. Examples Agent

**Papel:** Criador de exemplos Rust  
**Objetivo:** Mostrar uso real sem complicar a biblioteca.

Tarefas:

- Criar exemplos em `examples/` quando necessario.
- Exemplos recomendados:
  - `examples/sign_verify.rs`
  - `examples/with_claims.rs`
  - `examples/manager_integration.rs`
- Cada exemplo deve rodar com `cargo run --example nome`.
- Comentarios devem explicar apenas o que importa para uso e seguranca.

## 5. Docs Agent

**Papel:** Editor tecnico  
**Objetivo:** Manter documentacao curta, clara e pratica.

Tarefas:

- Atualizar `README.md` quando a API publica mudar.
- Documentar JWT nativo sem dependencias desnecessarias.
- Incluir tabela de options quando houver parametros novos.
- Incluir notas de seguranca para claims, algoritmos e segredo.
- Manter exemplos compilaveis.

## Workflow Sugerido

1. Refactor Agent ajusta a API e separa arquivos quando necessario.
2. Security Agent revisa assinatura, verificacao, claims e comparacao constante.
3. Test Agent adiciona ou atualiza testes.
4. Examples Agent cria exemplos pequenos e executaveis.
5. Docs Agent atualiza README e notas de seguranca.
6. Rodar `cargo fmt --check`, `cargo clippy --all-targets --all-features` e `cargo test`.

## Definicao De Pronto

Uma mudanca so esta pronta quando:

- Compila sem warnings relevantes.
- Passa em todos os testes.
- Mantem funcoes pequenas e mono tarefa.
- Nao aumenta dependencias sem motivo forte.
- Tem comentarios onde ha decisao de seguranca.
- A API publica continua facil de usar.
