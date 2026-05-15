# hash_token_rust

Gestionnaire de tokens leger en Rust pour binaires standalone, secrets partages, salts, controle d age et support JWT optionnel.

Documentation :

- English: `README.md`
- Portugues: `README.pt.md`
- Francais: `README.fr.md`

## A Quoi Sert Cette Bibliotheque

`hash_token_rust` sert a creer et verifier des tokens signes de maniere simple, previsible et facile a auditer.

Elle couvre deux usages principaux :

- Tokens HMAC avec secret et salts, geres par `AdvancedTokenManager`.
- JWT natifs signes avec HMAC via `HS256` ou `HS512`.

Utilisez ce projet quand des programmes standalone doivent echanger des donnees signees sans certificats, cles publiques, cles privees, frameworks ou beaucoup de dependances.

## Fonctionnement

Dans le flux natif `AdvancedTokenManager`, le manager conserve un secret partage et une liste de salts. Il genere un nouveau format versionne : `htr1.<payload>.<metadata>.<signature>`. Le payload et les metadata utilisent Base64URL. Les metadata contiennent la version, l.algorithme, l.index de salt, `iat`, `exp` optionnel, `iss` optionnel et `aud` optionnel. La signature authentifie la version, le payload et les metadata avec HMAC plus le salt choisi.

Dans le flux JWT, la bibliotheque construit un header JSON et un payload JSON, encode les deux segments en Base64URL sans padding, signe le texte `header.payload` avec HMAC et place la signature dans le troisieme segment. Lors de la verification, elle valide la structure, decode les segments, verifie l'algorithme, controle la signature puis valide les claims configurees.

## Exemple JWT Simple

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

`AdvancedTokenManager` est l.API principale. Il cree des tokens natifs `htr1` pour la communication entre binaires et expose aussi `generate_jwt` et `validate_jwt`. Par defaut, les JWT utilisent le secret du manager, mais chaque appel peut fournir son propre secret.

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

## Options JWT Importantes

| Option | Role |
| --- | --- |
| `algorithm` | Definit l'algorithme de signature. La valeur par defaut est `HS256`. |
| `algorithms` | Limite la verification aux algorithmes attendus. |
| `expires_in` | Ajoute `exp` relativement au moment de signature. |
| `not_before` | Ajoute `nbf` relativement au moment de signature. |
| `issued_at` | Definit `iat`; sinon la bibliotheque ajoute le timestamp courant. |
| `clock_tolerance` | Autorise un petit decalage d'horloge pendant la validation temporelle. |
| `max_age` | Rejette les tokens dont `iat` est trop ancien. |
| `audience` | Exige et valide `aud`. |
| `issuer` | Exige et valide `iss`. |
| `subject` | Exige et valide `sub`. |
| `max_payload_size` | Rejette les payloads JWT trop grands avant et apres decodage. |
| `allowed_claims` | Limite les claims personnalisees hors claims standard. |

## Modele De Securite

- `alg: none` est rejete.
- Seuls `HS256` et `HS512` exacts sont acceptes.
- Base64URL doit etre canonique et sans padding.
- Les segments vides, le JSON invalide et les claims de type invalide sont rejetes.
- Les signatures JWT et les signatures natives du manager sont compares sans sortie anticipee pour les entrees de meme taille.
- L'arithmetique temporelle utilise des operations checked.
- `exp`, `nbf`, `iat`, `iss`, `aud` et `sub` sont valides quand ils existent et obligatoires quand ils sont configures.

Utilisez des secrets forts, limitez les algorithmes acceptes lors de la verification et configurez `max_payload_size` sur les endpoints publics.

## Exemples

```bash
cargo run --example sign_verify
cargo run --example with_claims
cargo run --example manager_integration
```

## Developpement

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

Le code est separe par responsabilite : Base64URL, claims, signature, verification, temps, initialisation du manager, parsing de token et integration JWT du manager.
