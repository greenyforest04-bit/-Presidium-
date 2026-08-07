//! Crypto Box: sealed envelope encryption (NaCl-style)
//!
//! Uses X25519 + ChaCha20-Poly1305 with HPKE-style construction for
//! attaching encrypted files/media to messages.

use crate::constants::*;
use crate::error::{CryptoError, Result};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// A sealed crypto box: encrypted content to a recipient's public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoBox {
    /// Ephemeral public key (for key agreement)
    pub ephemeral_public: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Nonce used for encryption
    pub nonce: [u8; CHACHA20_POLY1305_NONCE_SIZE],
    /// Ciphertext (includes Poly1305 tag)
    pub ciphertext: Vec<u8>,
}

impl CryptoBox {
    /// Seal content to a recipient's public key
    pub fn seal(recipient_public: &[u8; X25519_PUBLIC_KEY_SIZE], plaintext: &[u8]) -> Result<Self> {
        // Generate ephemeral key pair
        let ephemeral_secret = X25519StaticSecret::random();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        let recipient_pub = X25519PublicKey::from(*recipient_public);

        // Shared secret via X25519 DH
        let shared = ephemeral_secret.diffie_hellman(&recipient_pub);

        // Derive symmetric key via HKDF
        let hkdf = Hkdf::<Sha256>::new(Some(b"presidium-cryptobox"), shared.as_bytes());
        let mut key = [0u8; CHACHA20_POLY1305_KEY_SIZE];
        hkdf.expand(b"sealed-key", &mut key)
            .map_err(|_| CryptoError::KeyDerivationFailed("CryptoBox key derivation failed".into()))?;

        // Generate nonce
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce);

        // Encrypt
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher.encrypt(
            (&nonce).into(),
            Payload { msg: plaintext, aad: ephemeral_public.as_bytes() }
        ).map_err(|_| CryptoError::EncryptionFailed("CryptoBox seal failed".into()))?;

        Ok(Self {
            ephemeral_public: ephemeral_public.to_bytes(),
            nonce,
            ciphertext,
        })
    }

    /// Open a sealed box with our private key
    pub fn open(&self, recipient_secret: &X25519StaticSecret) -> Result<Vec<u8>> {
        let ephemeral_pub = X25519PublicKey::from(self.ephemeral_public);
        let shared = recipient_secret.diffie_hellman(&ephemeral_pub);

        let hkdf = Hkdf::<Sha256>::new(Some(b"presidium-cryptobox"), shared.as_bytes());
        let mut key = [0u8; CHACHA20_POLY1305_KEY_SIZE];
        hkdf.expand(b"sealed-key", &mut key)
            .map_err(|_| CryptoError::KeyDerivationFailed("CryptoBox key derivation failed".into()))?;

        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher.decrypt(
            (&self.nonce).into(),
            Payload { msg: &self.ciphertext, aad: &self.ephemeral_public }
        ).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

/// Seal a message to a recipient
pub fn crypto_box_seal(recipient_public: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let boxed = CryptoBox::seal(recipient_public, plaintext)?;
    serde_json::to_vec(&boxed).map_err(CryptoError::from)
}

/// Open a sealed message
pub fn crypto_box_open(recipient_secret: &X25519StaticSecret, msg: &[u8]) -> Result<Vec<u8>> {
    let boxed: CryptoBox = serde_json::from_slice(msg).map_err(CryptoError::from)?;
    boxed.open(recipient_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_box_roundtrip() {
        let secret = X25519StaticSecret::random();
        let public = X25519PublicKey::from(&secret);
        let data = b"secret payload";

        let sealed = CryptoBox::seal(public.as_bytes(), data).unwrap();
        let opened = sealed.open(&secret).unwrap();
        assert_eq!(&opened[..], data);
    }

    #[test]
    fn test_seal_open_functions() {
        let secret = X25519StaticSecret::random();
        let public = X25519PublicKey::from(&secret);
        let data = b"message";

        let sealed = crypto_box_seal(public.as_bytes(), data).unwrap();
        let opened = crypto_box_open(&secret, &sealed).unwrap();
        assert_eq!(&opened[..], data);
    }
}