use crate::base64url;
use crate::error::TokenError;
use crate::meta::Meta;

pub(crate) fn meta(meta: &Meta) -> Result<String, TokenError> {
    let mut text = String::with_capacity(96);
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
    value
        .map(|text| base64url::encode(text.as_bytes()))
        .unwrap_or_default()
}

fn push_field(output: &mut String, value: &str) {
    output.push_str(value);
    output.push('|');
}
