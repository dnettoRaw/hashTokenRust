# hash_token_rust

Tokens natifs signes et scelles, minimaux, pour binaires Rust standalone.

`hash_token_rust` est fait pour de petits programmes qui doivent echanger des donnees avec des secrets partages sans importer une grosse pile d'authentification, des fichiers de cles publiques/privees, des certificats, des services, des frameworks ou JWT comme format principal.

Il fournit deux modes natifs de token :

```text
htr1.<payload_b64url>.<metadata_b64url>.<signature_b64url>
hte1.<ciphertext_b64url>.<metadata_b64url>.<nonce_b64url>
```

- `htr1` est signe : le payload est lisible, mais les modifications sont detectees.
- `hte1` est scelle : le payload est chiffre et authentifie.

## Pourquoi Ceci Existe

Ce crate est concu pour des binaires standalone qui appartiennent au meme systeme et peuvent partager un secret plus des salts. Un cas typique :

- le binaire A emet un petit payload ;
- le binaire B verifie que le payload vient de quelqu'un qui connait le secret ;
- les tokens peuvent expirer ;
- les tokens peuvent etre limites par issuer et audience ;
- les salts peuvent etre rotates ou selectionnes explicitement ;
- aucun `.pem`, `.pub`, chaine de certificats, service central ou framework lourd n'est requis.

Ce n'est pas une bibliotheque de hash de mot de passe. Ce n'est pas un remplacement pour Argon2, bcrypt ou scrypt. C'est un gestionnaire compact de tokens pour authentifier et, en mode scelle, chiffrer des donnees echangees entre binaires de confiance.

## Modes De Token

### Tokens Signes : `htr1`

Utilisez les tokens signes quand le payload peut etre lisible mais ne doit pas etre modifiable.

La signature authentifie :

- version du token ;
- payload encode ;
- metadata encode ;
- salt selectionne ;
- secret partage.

Bons usages :

- identifiants utilisateur ou job ;
- commandes qui ne sont pas secretes ;
- tokens courts de passage entre processus ;
- messages internes ou l'integrite compte.

### Tokens Scelles : `hte1`

Utilisez les tokens scelles quand le payload ne doit pas etre lisible par celui qui voit le token.

Les tokens scelles utilisent `ChaCha20-Poly1305`, un chiffrement AEAD. La cle de chiffrement est derivee du secret du manager et du salt selectionne. Les metadata et le nonce sont authentifies comme donnees associees, donc les modifier invalide le token.

Bons usages :

- donnees utilisateur sensibles ;
- messages internes prives ;
- payloads qui exigent integrite et confidentialite.

## Installation

```toml
[dependencies]
hash_token_rust = "0.3"
```

Avec le depot directement :

```toml
[dependencies]
hash_token_rust = { path = "../hashTokenRust" }
```

## Creer Un Manager

```rust
use hash_token_rust::{AdvancedTokenManager, Algorithm};

let mut manager = AdvancedTokenManager::new(
    b"very-secure-secret",
    &[b"salt-a".as_slice(), b"salt-b".as_slice()],
    Algorithm::Sha256,
)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Le manager a besoin de :

| Champ | Signification |
| --- | --- |
| `secret` | Secret partage connu par les binaires qui doivent se faire confiance. Minimum 16 octets. |
| `salts` | Un ou plusieurs salts non vides. L'index du salt selectionne est stocke dans les metadata. |
| `algorithm` | Algorithme HMAC pour tokens signes et derivation de cle. `Sha256` ou `Sha512`. |

## Exemple De Token Signe

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

Si vous avez seulement besoin du payload :

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

## Exemple De Token Scelle

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

## Payloads Binaires

Utilisez les APIs byte quand le payload n'est pas UTF-8.

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

Pour les payloads binaires chiffres :

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

| Option | Signification |
| --- | --- |
| `salt_index` | Selectionne un salt specifique. Si absent, un index aleatoire est utilise. |
| `expires_in` | Ajoute une expiration en secondes depuis `issued_at`. |
| `issuer` | Identifie qui a cree le token. |
| `audience` | Identifie qui doit accepter le token. |
| `issued_at` | Remplace le timestamp d'emission. Utile pour les tests. |

### `ValidateTokenOptions`

| Option | Signification |
| --- | --- |
| `max_age` | Rejette les tokens plus vieux que ce nombre de secondes selon `issued_at`. |
| `issuer` | Exige que l'issuer du token corresponde. |
| `audience` | Exige que l'audience du token corresponde. |
| `clock_tolerance` | Autorise un petit decalage d'horloge en secondes. |
| `clock_timestamp` | Remplace l'heure courante. Utile pour les tests. |

## Sortie Validee

`validate_token` et `open_token` retournent `VerifiedToken` :

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

Les APIs byte retournent `VerifiedBytes`, avec les memes metadata et un payload `Vec<u8>`.

## Rotation Des Salts

Les tokens stockent l'index du salt selectionne dans les metadata. Cela rend la rotation simple :

- gardez les anciens salts disponibles tant que les anciens tokens peuvent etre valides ;
- genereez les nouveaux tokens avec le nouvel index de salt ;
- supprimez les anciens salts seulement apres expiration de tous les anciens tokens.

Si les binaires ne partagent pas le meme secret et la meme liste de salts, la validation ou l'ouverture echoue.

## Notes De Securite

- `htr1` signe les donnees ; il ne les cache pas.
- `hte1` scelle les donnees ; il chiffre et authentifie le payload.
- Les tokens signes servent a l'authenticite et l'integrite.
- Les tokens scelles servent a l'authenticite, l'integrite et la confidentialite du payload.
- Utilisez des secrets partages a haute entropie.
- Faites tourner les salts deliberement.
- Gardez des durees de vie courtes quand les tokens traversent des processus ou machines.
- N'utilisez pas ceci comme hash de mot de passe.
- Si un secret partage fuite, les tokens de ce groupe de confiance doivent etre consideres compromis.

## Exemples

```bash
cargo run --example native_signed
```

## Developpement

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## Objectifs De Design

- Rust 2021.
- Fichiers petits et fonctions courtes.
- Erreurs claires avec `Result<T, TokenError>`.
- Dependances minimales.
- Pas de framework.
- Pas de dependance JWT.
- Pas de panic dans le code de bibliotheque pour les erreurs normales.
- Eviter les allocations inutiles quand le code peut rester clair.
