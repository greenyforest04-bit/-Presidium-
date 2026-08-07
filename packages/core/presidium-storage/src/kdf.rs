//! Database key derivation via Argon2id.
//!
//! The SQLCipher database is encrypted with a raw 32-byte key. The user
//! passphrase is stretched with Argon2id using parameters shared with the
//! crypto layer; the per-install salt is stored next to the database file
//! (outside the encrypted payload).

use argon2::{Algorithm, Argon2, Params, Version};
use presidium_crypto::constants::{
    ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_OUTPUT_SIZE, ARGON2_PARALLELISM, ARGON2_SALT_SIZE,
};
use zeroize::Zeroizing;

use crate::error::{Result, StorageError};

/// Size of the raw SQLCipher key, in bytes.
pub const DB_KEY_SIZE: usize = ARGON2_OUTPUT_SIZE;

/// Generate a random per-install salt of the canonical size.
pub fn generate_salt() -> [u8; ARGON2_SALT_SIZE] {
    uuid::Uuid::new_v4().into_bytes()
}

/// Stretch a passphrase into the raw SQLCipher database key.
///
/// Deterministic: the same passphrase and salt always produce the same key.
pub fn derive_db_key(passphrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; DB_KEY_SIZE]>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(DB_KEY_SIZE),
    )
    .map_err(|e| StorageError::KeyDerivation(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; DB_KEY_SIZE]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|e| StorageError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_deterministic() {
        let a = derive_db_key(b"hunter2", b"0123456789abcdef").unwrap();
        let b = derive_db_key(b"hunter2", b"0123456789abcdef").unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn different_passphrase_produces_different_key() {
        let a = derive_db_key(b"hunter2", b"0123456789abcdef").unwrap();
        let b = derive_db_key(b"hunter3", b"0123456789abcdef").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn different_salt_produces_different_key() {
        let a = derive_db_key(b"hunter2", b"0123456789abcdef").unwrap();
        let b = derive_db_key(b"hunter2", b"fedcba9876543210").unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn generated_salt_has_canonical_size() {
        assert_eq!(generate_salt().len(), ARGON2_SALT_SIZE);
    }
}
