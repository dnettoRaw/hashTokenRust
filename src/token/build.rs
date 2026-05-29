use crate::base64url;
use crate::error::TokenError;
use crate::manager::AdvancedTokenManager;
use crate::meta::Meta;
use crate::options::GenerateTokenOptions;
use crate::token::parts::signing_input;
use crate::token::VERSION;

pub(crate) fn token(
    manager: &mut AdvancedTokenManager,
    payload: &[u8],
    options: &GenerateTokenOptions<'_>,
) -> Result<String, TokenError> {
    let salt_index = manager.select_salt(options.salt_index)?;
    let meta = meta(manager, salt_index, options)?;
    let encoded_payload = base64url::encode(payload);
    let encoded_meta = meta.encode()?;
    let signature = manager.sign(
        signing_input(&encoded_payload, &encoded_meta).as_bytes(),
        salt_index,
    )?;
    assemble(
        &encoded_payload,
        &encoded_meta,
        &base64url::encode(&signature),
    )
}

fn meta(
    manager: &AdvancedTokenManager,
    salt_index: usize,
    options: &GenerateTokenOptions<'_>,
) -> Result<Meta, TokenError> {
    let issued_at = options.issued_at.map_or_else(crate::validate::now, Ok)?;
    Ok(Meta {
        algorithm: manager.algorithm.name().to_string(),
        salt_index,
        issued_at,
        expires_at: expiration(issued_at, options.expires_in)?,
        issuer: options.issuer.map(str::to_string),
        audience: options.audience.map(str::to_string),
    })
}

fn assemble(payload: &str, meta: &str, signature: &str) -> Result<String, TokenError> {
    let mut token =
        String::with_capacity(VERSION.len() + payload.len() + meta.len() + signature.len() + 3);
    token.push_str(VERSION);
    token.push('.');
    token.push_str(payload);
    token.push('.');
    token.push_str(meta);
    token.push('.');
    token.push_str(signature);
    Ok(token)
}

fn expiration(issued_at: u64, expires_in: Option<u64>) -> Result<Option<u64>, TokenError> {
    expires_in
        .map(|seconds| {
            issued_at
                .checked_add(seconds)
                .ok_or_else(|| TokenError::new("Token expiration overflow."))
        })
        .transpose()
}
