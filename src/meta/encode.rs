//! Metadata encoding for the compact native format.
//!
//! Text claims are encoded as Base64URL inside metadata before the whole
//! metadata block is encoded. That keeps separators unambiguous.
use crate::base64url;
use crate::error::TokenError;
use crate::meta::Meta;

pub(crate) fn meta(meta: &Meta) -> Result<String, TokenError> {
    // A metadata e texto pequeno e previsivel. Reservar um pouco reduz realocacao
    // sem tentar calcular cada byte antes da hora.
    let mut text = String::with_capacity(96);
    // Campos fixos e sempre na mesma ordem. Se mudar a ordem, muda o formato.
    push_field(&mut text, &meta.algorithm);
    push_field(&mut text, &meta.salt_index.to_string());
    push_field(&mut text, &meta.issued_at.to_string());
    push_field(
        &mut text,
        &meta
            .expires_at
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    push_field(&mut text, &super::encode_optional(meta.issuer.as_deref()));
    text.push_str(&super::encode_optional(meta.audience.as_deref()));
    Ok(base64url::encode(text.as_bytes()))
}

pub(crate) fn encode_optional(value: Option<&str>) -> String {
    // Campo vazio representa None. Campo presente passa por Base64URL para nunca
    // quebrar o separador interno '|'.
    value
        .map(|text| base64url::encode(text.as_bytes()))
        .unwrap_or_default()
}

fn push_field(output: &mut String, value: &str) {
    // Separador simples porque claims textuais ja foram escapadas por Base64URL.
    output.push_str(value);
    output.push('|');
}
