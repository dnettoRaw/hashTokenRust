use crate::error::TokenError;
use crate::sealed::VERSION;

pub(crate) struct Parts<'a> {
    pub ciphertext: &'a str,
    pub meta: &'a str,
    pub nonce: &'a str,
}

pub(crate) fn split(token: &str) -> Result<Parts<'_>, TokenError> {
    let mut fields = token.split('.');
    let version = fields.next().unwrap_or_default();
    let ciphertext = fields.next().unwrap_or_default();
    let meta = fields.next().unwrap_or_default();
    let nonce = fields.next().unwrap_or_default();
    reject_bad_shape(version, ciphertext, meta, nonce, fields.next())?;
    Ok(Parts {
        ciphertext,
        meta,
        nonce,
    })
}

pub(crate) fn aad(meta: &str, nonce: &str) -> String {
    let mut input = String::with_capacity(VERSION.len() + meta.len() + nonce.len() + 2);
    input.push_str(VERSION);
    input.push('.');
    input.push_str(meta);
    input.push('.');
    input.push_str(nonce);
    input
}

fn reject_bad_shape(
    version: &str,
    ciphertext: &str,
    meta: &str,
    nonce: &str,
    extra: Option<&str>,
) -> Result<(), TokenError> {
    if version != VERSION
        || ciphertext.is_empty()
        || meta.is_empty()
        || nonce.is_empty()
        || extra.is_some()
    {
        Err(TokenError::new("Invalid sealed token structure."))
    } else {
        Ok(())
    }
}
