use zenth_crypto::hashing::hash::CryptographicHash;
use crate::db::error::{
    HashError
};
use rand::RngExt;
use zeroize::Zeroizing;

/// Taille du salt en bytes (32 bytes = 256 bits)
pub const SALT_SIZE: usize = 32;

/// Taille de la cle SQLCipher derivee (32 bytes = 256 bits)
pub const KEY_SIZE: usize = 32;

/// Genere un salt aleatoire cryptographiquement sur
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill(&mut salt);
    salt
}

/// Convertit une cle binaire en chaine hexadecimale pour SQLCipher
/// Format: "x'<hex>'"
pub fn key_to_sqlcipher_pragma(key: &[u8; KEY_SIZE]) -> Zeroizing<String> {
    let hex_key = hex::encode(key);
    Zeroizing::new(format!("x'{}'", hex_key))
}

/// Hash le nom d'utilisateur avec SHA256 pour creer un identifiant de BDD
/// Retourne les 16 premiers caracteres hex (8 bytes)
pub fn hash_username(username: &str) -> Result<String, HashError> {
    let mut hasher = CryptographicHash::new(
        "SHA256", 1
    ).map_err(|_| HashError::HashError)?;
    hasher.update(username.as_bytes());
    let result = hasher.finalize();
    // 16 caracteres hex
    Ok(hex::encode(&result[..8]))
}


