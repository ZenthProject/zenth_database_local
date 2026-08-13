use zenth_crypto::kdf::argon2id::Argon2idHasher;
use zenth_database_local::db::crypto::{
    SALT_SIZE, 
    generate_salt, 
    hash_username
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), SALT_SIZE);
    }

    #[test]
    fn test_derive_key() {
        let salt = generate_salt();
        let key1 = Argon2idHasher::derive_sqlcipher_key("password123", &salt).unwrap();
        let key2 = Argon2idHasher::derive_sqlcipher_key("password123", &salt).unwrap();
        let key3 = Argon2idHasher::derive_sqlcipher_key("different", &salt).unwrap();

        assert_eq!(*key1, *key2);
        assert_ne!(*key1, *key3);
    }

    #[test]
    fn test_hash_username() {
        let hash1 = hash_username("alice").unwrap();
        let hash2 = hash_username("alice").unwrap();
        let hash3 = hash_username("bob").unwrap();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16);
    }
}