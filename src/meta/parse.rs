use crate::error::TokenError;

pub(crate) fn required<'a>(value: &'a str, name: &str) -> Result<&'a str, TokenError> {
    if value.is_empty() {
        Err(TokenError::new(format!("Missing {}.", name)))
    } else {
        Ok(value)
    }
}

pub(crate) fn parse_usize(value: &str, name: &str) -> Result<usize, TokenError> {
    required(value, name)?
        .parse()
        .map_err(|_| TokenError::new(format!("Invalid {}.", name)))
}

pub(crate) fn parse_u64(value: &str, name: &str) -> Result<u64, TokenError> {
    required(value, name)?
        .parse()
        .map_err(|_| TokenError::new(format!("Invalid {}.", name)))
}

pub(crate) fn parse_optional_u64(value: &str, name: &str) -> Result<Option<u64>, TokenError> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_u64(value, name).map(Some)
    }
}
