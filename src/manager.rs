use rand::Rng;

use crate::crypto;
use crate::error::TokenError;

const MIN_SECRET_LENGTH: usize = 16;
const MIN_SALT_COUNT: usize = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "HS256",
            Algorithm::Sha512 => "HS512",
        }
    }
}

pub struct AdvancedTokenManager {
    pub(crate) secret: Vec<u8>,
    pub(crate) salts: Vec<Vec<u8>>,
    pub(crate) algorithm: Algorithm,
    last_salt_index: Option<usize>,
}

impl AdvancedTokenManager {
    pub fn new(secret: &[u8], salts: &[&[u8]], algorithm: Algorithm) -> Result<Self, TokenError> {
        validate_secret(secret)?;
        validate_salts(salts)?;
        Ok(Self {
            secret: secret.to_vec(),
            salts: salts.iter().map(|salt| salt.to_vec()).collect(),
            algorithm,
            last_salt_index: None,
        })
    }

    pub(crate) fn select_salt(&mut self, requested: Option<usize>) -> Result<usize, TokenError> {
        match requested {
            Some(index) => self.validate_salt_index(index).map(|_| index),
            None => Ok(self.random_salt_index()),
        }
    }

    pub(crate) fn validate_salt_index(&self, index: usize) -> Result<(), TokenError> {
        if index < self.salts.len() {
            Ok(())
        } else {
            Err(TokenError::new("Invalid salt index."))
        }
    }

    pub(crate) fn sign(
        &self,
        signing_input: &[u8],
        salt_index: usize,
    ) -> Result<Vec<u8>, TokenError> {
        crypto::sign(
            self.algorithm,
            &self.secret,
            &self.salts[salt_index],
            signing_input,
        )
    }

    fn random_salt_index(&mut self) -> usize {
        let mut rng = rand::thread_rng();
        loop {
            let index = rng.gen_range(0..self.salts.len());
            if Some(index) != self.last_salt_index || self.salts.len() == 1 {
                self.last_salt_index = Some(index);
                return index;
            }
        }
    }
}

fn validate_secret(secret: &[u8]) -> Result<(), TokenError> {
    if secret.len() < MIN_SECRET_LENGTH {
        Err(TokenError::new("Secret must be at least 16 bytes."))
    } else {
        Ok(())
    }
}

fn validate_salts(salts: &[&[u8]]) -> Result<(), TokenError> {
    if salts.len() < MIN_SALT_COUNT || salts.iter().any(|salt| salt.is_empty()) {
        Err(TokenError::new("At least one non-empty salt is required."))
    } else {
        Ok(())
    }
}
