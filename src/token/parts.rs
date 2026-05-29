//! Signed-token splitting and signing input assembly.

use crate::error::TokenError;
use crate::token::VERSION;

pub(crate) struct Parts<'a> {
    pub payload: &'a str,
    pub meta: &'a str,
    pub signature: &'a str,
}

pub(crate) fn split(token: &str) -> Result<Parts<'_>, TokenError> {
    // Token assinado tem 4 partes fixas. Nao tentamos recuperar formato quebrado.
    let mut fields = token.split('.');
    let version = fields.next().unwrap_or_default();
    let payload = fields.next().unwrap_or_default();
    let meta = fields.next().unwrap_or_default();
    let signature = fields.next().unwrap_or_default();
    reject_bad_shape(version, payload, meta, signature, fields.next())?;
    Ok(Parts {
        payload,
        meta,
        signature,
    })
}

pub(crate) fn signing_input(payload: &str, meta: &str) -> String {
    // A assinatura cobre exatamente o que sera transportado antes dela.
    // Isso evita diferenca entre bytes assinados e bytes serializados.
    let mut input = String::with_capacity(VERSION.len() + payload.len() + meta.len() + 2);
    input.push_str(VERSION);
    input.push('.');
    input.push_str(payload);
    input.push('.');
    input.push_str(meta);
    input
}

fn reject_bad_shape(
    version: &str,
    payload: &str,
    meta: &str,
    signature: &str,
    extra: Option<&str>,
) -> Result<(), TokenError> {
    // Segmentos vazios sao rejeitados antes de Base64URL para dar erro de
    // estrutura, nao erro criptico de encoding.
    if version != VERSION
        || payload.is_empty()
        || meta.is_empty()
        || signature.is_empty()
        || extra.is_some()
    {
        Err(TokenError::new("Invalid token structure."))
    } else {
        Ok(())
    }
}
