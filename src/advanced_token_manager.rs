use std::env;
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const DEFAULT_SECRET_LENGTH: usize = 32;
const DEFAULT_SALT_COUNT: usize = 10;
const DEFAULT_SALT_LENGTH: usize = 16;
const MIN_SECRET_LENGTH: usize = 16;
const MIN_SALT_COUNT: usize = 2;

pub enum Algorithm {
    Sha256,
    Sha512,
}

pub struct AdvancedTokenManager {
    secret: String,
    salts: Vec<String>,
    algorithm: Algorithm,
    last_salt_index: Option<usize>,
}

impl AdvancedTokenManager {
    pub fn new(
        secret: Option<String>,
        salts: Option<Vec<String>>,
        algorithm: Option<Algorithm>,
        allow_auto_generate: bool,
        no_env: bool,
    ) -> Result<Self, String> {
        let secret: String = Self::initialize_secret(secret, allow_auto_generate, no_env)?;
        let salts: Vec<String> = Self::initialize_salts(salts, allow_auto_generate, no_env)?;
        let algorithm: Algorithm = algorithm.unwrap_or(Algorithm::Sha256);

        Ok(Self {
            secret,
            salts,
            algorithm,
            last_salt_index: None,
        })
    }

    fn initialize_secret(
        secret: Option<String>,
        allow_auto_generate: bool,
        no_env: bool,
    ) -> Result<String, String> {
        let secret: Option<String> = if !no_env {
            secret.or_else(|| env::var("TOKEN_SECRET").ok())
        } else {
            secret
        };

        match secret {
            Some(secret) if secret.len() >= MIN_SECRET_LENGTH => Ok(secret),
            Some(_) => Err(format!(
                "Secret must be at least {} characters long.",
                MIN_SECRET_LENGTH
            )),
            None if allow_auto_generate => {
                let generated_secret = Self::generate_random_key(DEFAULT_SECRET_LENGTH);
                eprintln!("⚠️ Secret generated automatically. Store it securely.");
                Ok(generated_secret)
            }
            None => Err("Secret is required and must meet minimum length requirements.".to_string()),
        }
    }

    fn initialize_salts(
        salts: Option<Vec<String>>,
        allow_auto_generate: bool,
        no_env: bool,
    ) -> Result<Vec<String>, String> {
        let salts: Option<Vec<String>> = if !no_env {
            salts.or_else(|| env::var("TOKEN_SALTS").ok().map(|s: String| s.split(',').map(String::from).collect()))
        } else {
            salts
        };

        match salts {
            Some(salts) if salts.len() >= MIN_SALT_COUNT && salts.iter().all(|s: &String| !s.trim().is_empty()) => Ok(salts),
            Some(_) => Err(format!(
                "Salt array must have at least {} non-empty elements.",
                MIN_SALT_COUNT
            )),
            None if allow_auto_generate => {
                let generated_salts: Vec<String> = (0..DEFAULT_SALT_COUNT)
                    .map(|_| Self::generate_random_key(DEFAULT_SALT_LENGTH))
                    .collect();
                eprintln!("⚠️ Salts generated automatically. Store them securely.");
                Ok(generated_salts)
            }
            None => Err("Salts are required and must meet minimum requirements.".to_string()),
        }
    }

    fn generate_random_key(length: usize) -> String {
        let characters: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        (0..length)
            .map(|_| characters[rng.gen_range(0..characters.len())])
            .collect()
    }

    fn get_random_salt_index(&mut self) -> usize {
        let mut index: usize;
        loop {
            index = rand::random::<usize>() % self.salts.len();
            if Some(index) != self.last_salt_index {
                break;
            }
        }
        self.last_salt_index = Some(index);
        index
    }

    pub fn generate_token(&mut self, input: &str, salt_index: Option<usize>) -> String {
        let index: usize = salt_index.unwrap_or_else(|| self.get_random_salt_index());
        self.validate_salt_index(index).unwrap();
        let salt: &String = &self.salts[index];
        let checksum: String = self.create_checksum(input, salt);
        general_purpose::STANDARD.encode(format!("{}|{}|{}", input, index, checksum))
    }
    
    pub fn validate_token(&self, token: &str) -> Option<String> {
        let decoded: String = match general_purpose::STANDARD.decode(token) {
            Ok(decoded) => String::from_utf8(decoded).ok()?,
            Err(_) => return None,
        };
    
        let parts: Vec<&str> = decoded.split('|').collect();
        if parts.len() != 3 {
            return None;
        }
    
        let input: &str = parts[0];
        let salt_index: usize = parts[1].parse().ok()?;
        let checksum: &str = parts[2];
    
        self.validate_salt_index(salt_index).ok()?;
        let valid_checksum: String = self.create_checksum(input, &self.salts[salt_index]);
    
        if valid_checksum == checksum {
            Some(input.to_string())
        } else {
            None
        }
    }

    fn validate_salt_index(&self, index: usize) -> Result<(), String> {
        if index < self.salts.len() {
            Ok(())
        } else {
            Err(format!("Invalid salt index: {}", index))
        }
    }

    fn create_checksum(&self, input: &str, salt: &str) -> String {
        match self.algorithm {
            Algorithm::Sha256 => {
                let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes()).expect("Invalid HMAC key");
                mac.update(format!("{}{}", input, salt).as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
            Algorithm::Sha512 => {
                let mut mac = HmacSha512::new_from_slice(self.secret.as_bytes()).expect("Invalid HMAC key");
                mac.update(format!("{}{}", input, salt).as_bytes());
                hex::encode(mac.finalize().into_bytes())
            }
        }
    }
}
