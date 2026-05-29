//! Small parsing helpers for metadata numeric fields.
use crate::error::TokenError;

pub(crate) fn required<'a>(value: &'a str, name: &str) -> Result<&'a str, TokenError> {
    // Campos obrigatorios vazios geralmente significam metadata corrompida ou
    // token montado manualmente de forma errada.
    if value.is_empty() {
        Err(TokenError::new(format!("Missing {}.", name)))
    } else {
        Ok(value)
    }
}

pub(crate) fn parse_usize(value: &str, name: &str) -> Result<usize, TokenError> {
    // Salt index precisa ser numero local; a validacao de faixa acontece no manager.
    required(value, name)?
        .parse()
        .map_err(|_| TokenError::new(format!("Invalid {}.", name)))
}

pub(crate) fn parse_u64(value: &str, name: &str) -> Result<u64, TokenError> {
    // Timestamps sao segundos UNIX para manter o formato portavel entre binarios.
    required(value, name)?
        .parse()
        .map_err(|_| TokenError::new(format!("Invalid {}.", name)))
}

pub(crate) fn parse_optional_u64(value: &str, name: &str) -> Result<Option<u64>, TokenError> {
    // Expiracao vazia significa token sem exp interno; max_age ainda pode limitar.
    if value.is_empty() {
        Ok(None)
    } else {
        parse_u64(value, name).map(Some)
    }
}
