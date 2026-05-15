use std::env;

pub(super) fn resolve_secret_candidate(secret: Option<String>, no_env: bool) -> Option<String> {
    let provided = secret.map(|value| value.trim().to_string());
    if no_env || provided.is_some() {
        provided
    } else {
        env::var("TOKEN_SECRET")
            .ok()
            .map(|value| value.trim().to_string())
    }
}

pub(super) fn resolve_salt_candidates(
    salts: Option<Vec<String>>,
    no_env: bool,
) -> Option<Vec<String>> {
    if no_env || salts.as_ref().is_some_and(|values| !values.is_empty()) {
        salts
    } else {
        env::var("TOKEN_SALTS").ok().map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .collect()
        })
    }
}
