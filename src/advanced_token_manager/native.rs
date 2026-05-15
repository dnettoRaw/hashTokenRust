use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(super) struct NativeTokenMeta {
    pub v: u8,
    pub alg: String,
    pub salt: usize,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
}

pub(super) struct NativeTokenParts {
    pub payload: String,
    pub meta: NativeTokenMeta,
    pub signing_input: String,
    pub signature: String,
}

pub(super) const TOKEN_VERSION: &str = "htr1";
