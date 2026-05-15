use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;

const CHARACTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub(super) fn generate_random_key(length: usize) -> String {
    let distribution = Uniform::from(0..CHARACTERS.len());
    let mut rng = OsRng;
    (0..length)
        .map(|_| CHARACTERS[distribution.sample(&mut rng)] as char)
        .collect()
}
