//! Metadata decoding and field-count validation.
//!
//! The parser is intentionally fixed-width: changing the number of fields must
//! be a format version change, not something accepted silently.
use crate::base64url;
use crate::error::TokenError;
use crate::meta::Meta;

pub(crate) fn meta(encoded: &str) -> Result<Meta, TokenError> {
    // Metadata tambem usa o decoder estrito. Se houver padding, caractere estranho
    // ou representacao nao canonica, o token cai fora cedo.
    let bytes = base64url::decode(encoded, "metadata")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| TokenError::new("Metadata is not UTF-8."))?;
    parse_meta(text)
}

pub(crate) fn decode_optional(value: &str, name: &str) -> Result<Option<String>, TokenError> {
    // Em metadata, string vazia e ausencia do campo; string presente precisa ser
    // Base64URL valido e UTF-8.
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = base64url::decode(value, name)?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| TokenError::new(format!("{} is not UTF-8.", name)))
}

fn parse_meta(text: &str) -> Result<Meta, TokenError> {
    // Parser propositalmente chato: cada campo tem posicao fixa e erro claro.
    let mut fields = text.split('|');
    let meta = Meta {
        algorithm: super::required(next(&mut fields)?, "algorithm")?.to_string(),
        salt_index: super::parse_usize(next(&mut fields)?, "salt")?,
        issued_at: super::parse_u64(next(&mut fields)?, "iat")?,
        expires_at: super::parse_optional_u64(next(&mut fields)?, "exp")?,
        issuer: super::decode_optional(next(&mut fields)?, "issuer")?,
        audience: super::decode_optional(next(&mut fields)?, "audience")?,
    };
    reject_extra(fields)?;
    Ok(meta)
}

fn next<'a>(fields: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, TokenError> {
    // Faltar campo e erro de estrutura, nao valor vazio.
    fields
        .next()
        .ok_or_else(|| TokenError::new("Invalid metadata field count."))
}

fn reject_extra<'a>(mut fields: impl Iterator<Item = &'a str>) -> Result<(), TokenError> {
    // Campo extra indica formato desconhecido. Melhor rejeitar do que tentar
    // interpretar parcialmente.
    if fields.next().is_some() {
        Err(TokenError::new("Invalid metadata field count."))
    } else {
        Ok(())
    }
}
