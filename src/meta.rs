mod decode;
mod encode;
mod parse;

pub(crate) use decode::decode_optional;
pub(crate) use encode::encode_optional;
pub(crate) use parse::{parse_optional_u64, parse_u64, parse_usize, required};

use crate::error::TokenError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Meta {
    pub algorithm: String,
    pub salt_index: usize,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl Meta {
    pub(crate) fn encode(&self) -> Result<String, TokenError> {
        encode::meta(self)
    }

    pub(crate) fn decode(encoded: &str) -> Result<Self, TokenError> {
        decode::meta(encoded)
    }
}
