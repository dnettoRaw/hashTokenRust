mod build;
mod parse;
mod validate;

use rand::Rng;

use super::native::NativeTokenMeta;
use super::{
    AdvancedTokenManager, GenerateTokenOptions, TokenValidationError, ValidateTokenOptions,
};

impl AdvancedTokenManager {
    pub fn generate_token(
        &mut self,
        input: &str,
        salt_index: Option<usize>,
    ) -> Result<String, TokenValidationError> {
        self.generate_token_with_options(
            input,
            Some(GenerateTokenOptions {
                salt_index,
                ..Default::default()
            }),
        )
    }

    pub fn generate_token_with_options(
        &mut self,
        input: &str,
        options: Option<GenerateTokenOptions>,
    ) -> Result<String, TokenValidationError> {
        let options = options.unwrap_or_default();
        let index = self.resolve_salt_index(options.salt_index)?;
        let meta = self.build_meta(index, &options)?;
        let signing_input = self.create_signature_input(input, &meta)?;
        let signature = self.sign_native_input(&signing_input, index)?;
        build::build_token(input, &meta, &signature)
    }

    pub fn validate_token(&self, token: &str) -> Result<Option<String>, TokenValidationError> {
        self.validate_token_with_options(token, None)
    }

    pub fn validate_token_with_options(
        &self,
        token: &str,
        options: Option<ValidateTokenOptions>,
    ) -> Result<Option<String>, TokenValidationError> {
        let options = options.unwrap_or_default();
        let should_throw = options
            .throw_on_failure
            .unwrap_or(self.throw_on_validation_failure);

        match self.validate_token_internal(token, &options) {
            Ok(value) => Ok(Some(value)),
            Err(error) if should_throw => Err(error),
            Err(error) => {
                self.logger
                    .error(&format!("Error validating token: {}", error));
                Ok(None)
            }
        }
    }

    pub fn validate_token_lenient(&self, token: &str) -> Option<String> {
        self.validate_token(token).ok().flatten()
    }

    pub fn extract_data(&self, token: &str) -> Result<Option<String>, TokenValidationError> {
        self.validate_token(token)
    }
}

impl AdvancedTokenManager {
    fn validate_token_internal(
        &self,
        token: &str,
        options: &ValidateTokenOptions,
    ) -> Result<String, TokenValidationError> {
        let parts = parse::parse_token(token)?;
        self.validate_salt_index(parts.meta.salt)?;
        validate::validate_metadata(&parts.meta, options)?;
        validate::verify_scope(&parts.meta, options)?;
        validate::verify_signature(self, &parts)?;
        Ok(parts.payload)
    }

    fn build_meta(
        &mut self,
        index: usize,
        options: &GenerateTokenOptions,
    ) -> Result<NativeTokenMeta, TokenValidationError> {
        let issued_at = super::time::current_timestamp(options.issued_at)?;
        Ok(NativeTokenMeta {
            v: 1,
            alg: self.algorithm.name().to_string(),
            salt: index,
            iat: issued_at,
            exp: build::expiration(issued_at, options.expires_in)?,
            iss: options.issuer.clone(),
            aud: options.audience.clone(),
        })
    }

    fn resolve_salt_index(
        &mut self,
        salt_index: Option<usize>,
    ) -> Result<usize, TokenValidationError> {
        match salt_index {
            Some(index) => {
                self.validate_salt_index(index)?;
                Ok(index)
            }
            None => Ok(self.get_random_salt_index()),
        }
    }

    pub(super) fn validate_salt_index(&self, index: usize) -> Result<(), TokenValidationError> {
        if index < self.salts.len() {
            Ok(())
        } else {
            Err(TokenValidationError::new(format!(
                "Invalid salt index: {}",
                index
            )))
        }
    }

    pub(super) fn create_signature_input(
        &self,
        payload: &str,
        meta: &NativeTokenMeta,
    ) -> Result<String, TokenValidationError> {
        build::signing_input(payload, meta)
    }

    pub(super) fn sign_native_input(
        &self,
        signing_input: &str,
        salt_index: usize,
    ) -> Result<String, TokenValidationError> {
        let mut material =
            String::with_capacity(signing_input.len() + self.salts[salt_index].len());
        material.push_str(signing_input);
        material.push_str(&self.salts[salt_index]);
        let digest = self
            .algorithm
            .to_hmac(self.secret.as_bytes(), material.as_bytes())?;
        Ok(hex::encode(digest))
    }

    fn get_random_salt_index(&mut self) -> usize {
        let len = self.salts.len();
        let mut rng = rand::thread_rng();
        loop {
            let index = rng.gen_range(0..len);
            if Some(index) != self.last_salt_index {
                self.last_salt_index = Some(index);
                return index;
            }
        }
    }
}
