//! Session keys, sender keys, and media keys
//!
//! High-level key containers built on top of the Double Ratchet and
//! group sender key primitives.

use crate::constants::*;
use crate::error::{CryptoError, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};
use crate::ratchet::{DoubleRatchet, RootKey};
use crate::identity::IdentityPublicKey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

/// HKDF info strings for key derivation
pub const HKDF_INFO: [&str; 3] = ["presidium-session", "presidium-sender", "presidium-media"];
/// HKDF info string for chain key derivation
pub const CHAIN_KEY_INFO: &[u8] = b"presidium-chain-key";
/// HKDF info string for root key derivation
pub const ROOT_KEY_INFO: &[u8] = b"presidium-root-key";
/// HKDF info string for message key derivation
pub const MESSAGE_KEY_INFO: &[u8] = b"presidium-message-key";

/// Long-lived session keys for a conversation
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SessionKeys {
    /// Our role in this session (initiator or responder)
    pub is_initiator: bool,
    /// Root key of the Double Ratchet
    pub root_key: [u8; ROOT_KEY_SIZE],
    /// Sending chain key
    pub sending_chain: [u8; CHAIN_KEY_SIZE],
    /// Receiving chain key
    pub receiving_chain: [u8; CHAIN_KEY_SIZE],
    /// Peer's identity public key
    pub peer_identity: IdentityPublicKey,
    /// Session counter
    pub message_count: u64,
}

impl SessionKeys {
    /// Construct a new session from a PQXDH shared secret.
    ///
    /// Root and chain keys are derived deterministically via HKDF-SHA256,
    /// so both peers derive identical key material from the same secret.
    pub fn new(
        is_initiator: bool,
        shared_secret: &[u8; 32],
        peer_identity: IdentityPublicKey,
    ) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut root_key = [0u8; ROOT_KEY_SIZE];
        hk.expand(b"ROOT_KEY", &mut root_key)
            .map_err(|_| CryptoError::KeyDerivationFailed("Root key derivation failed".into()))?;

        let mut sending_chain = [0u8; CHAIN_KEY_SIZE];
        hk.expand(b"SENDING_CHAIN", &mut sending_chain)
            .map_err(|_| CryptoError::KeyDerivationFailed("Sending chain derivation failed".into()))?;

        let mut receiving_chain = [0u8; CHAIN_KEY_SIZE];
        hk.expand(b"RECEIVING_CHAIN", &mut receiving_chain)
            .map_err(|_| CryptoError::KeyDerivationFailed("Receiving chain derivation failed".into()))?;

        Ok(Self {
            is_initiator,
            root_key,
            sending_chain,
            receiving_chain,
            peer_identity,
            message_count: 0,
        })
    }

    /// Increment message counter
    pub fn increment_count(&mut self) {
        self.message_count = self.message_count.saturating_add(1);
    }

    /// Rotate session keys if threshold reached
    pub fn needs_rotation(&self) -> bool {
        self.message_count >= KEY_ROTATION_MESSAGE_COUNT
    }

    /// Build a Double Ratchet session from these keys.
    ///
    /// The initiator needs the peer's ratchet public key; the responder
    /// derives its receiving chain lazily on the first message.
    pub fn to_ratchet(
        &self,
        our_dh_key: X25519StaticSecret,
        peer_dh_public: Option<X25519PublicKey>,
    ) -> Result<DoubleRatchet> {
        let root_key = RootKey::new(self.root_key);
        if self.is_initiator {
            let peer = peer_dh_public.ok_or_else(|| {
                CryptoError::InvalidParameter("Peer ratchet public key required".into())
            })?;
            DoubleRatchet::init(
                "presidium-session".to_string(),
                root_key,
                our_dh_key,
                peer,
                Vec::new(),
            )
        } else {
            DoubleRatchet::init_as_responder(
                "presidium-session".to_string(),
                root_key,
                our_dh_key,
                Vec::new(),
            )
        }
    }
}

/// Sender key for group encryption (Diffie-Hellman group session)
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SenderKeys {
    /// Sender key chain
    pub chain_key: [u8; CHAIN_KEY_SIZE],
    /// Group ID
    pub group_id: Vec<u8>,
    /// Sender identity (member public key)
    pub sender_identity: IdentityKey,
    /// Message index
    pub message_index: u64,
    /// Sender key ID
    pub key_id: u64,
}

impl SenderKeys {
    /// Create new sender keys for a group
    pub fn new(group_id: &[u8], sender: &IdentityKey) -> Result<Self> {
        let mut chain_key = [0u8; CHAIN_KEY_SIZE];
        rand::rng().fill_bytes(&mut chain_key);
        Ok(Self {
            chain_key,
            group_id: group_id.to_vec(),
            sender_identity: sender.clone(),
            message_index: 0,
            key_id: 1,
        })
    }

    /// Encrypt a message with the sender key
    pub fn encrypt(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        // Derive message key from chain key
        let digest = hmac_sha256(&self.chain_key, MESSAGE_KEY_INFO)?;
        let mut msg_key = [0u8; MESSAGE_KEY_SIZE];
        msg_key.copy_from_slice(&digest[..MESSAGE_KEY_SIZE]);

        // Advance chain
        let next = hmac_sha256(&self.chain_key, b"presidium-sender-advance")?;
        let mut new_chain = [0u8; CHAIN_KEY_SIZE];
        new_chain.copy_from_slice(&next[..CHAIN_KEY_SIZE]);
        self.chain_key = new_chain;

        // Encrypt with the current message number
        let nonce_index = self.message_index;
        self.message_index += 1;
        let cipher = ChaCha20Poly1305::new((&msg_key).into());
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        nonce[4..].copy_from_slice(&nonce_index.to_le_bytes());
        let ciphertext = cipher.encrypt(
            &nonce.into(),
            Payload { msg: plaintext, aad: associated_data }
        ).map_err(|_| CryptoError::EncryptionFailed("Sender key encryption failed".into()))?;
        Ok(ciphertext)
    }

    /// Decrypt a sender key message
    pub fn decrypt(&mut self, ciphertext: &[u8], index: u64, associated_data: &[u8]) -> Result<Vec<u8>> {
        let digest = hmac_sha256(&self.chain_key, MESSAGE_KEY_INFO)?;
        let mut msg_key = [0u8; MESSAGE_KEY_SIZE];
        msg_key.copy_from_slice(&digest[..MESSAGE_KEY_SIZE]);

        let cipher = ChaCha20Poly1305::new((&msg_key).into());
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        nonce[4..].copy_from_slice(&index.to_le_bytes());
        let plaintext = cipher.decrypt(
            &nonce.into(),
            Payload { msg: ciphertext, aad: associated_data }
        ).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }

    /// Advance the sender key chain by one message.
    ///
    /// Receivers must call this after each successfully decrypted message
    /// to keep the chain in sync with the sender (the chain advances on the
    /// encrypt side automatically).
    pub fn advance(&mut self) -> Result<()> {
        let next = hmac_sha256(&self.chain_key, b"presidium-sender-advance")?;
        self.chain_key.copy_from_slice(&next[..CHAIN_KEY_SIZE]);
        self.message_index = self.message_index.saturating_add(1);
        Ok(())
    }
}

/// Wrapper for a sender key message envelope
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderKeyMessage {
    /// Group ID
    pub group_id: Vec<u8>,
    /// Sender identity
    pub sender_identity: IdentityKey,
    /// Message index
    pub message_index: u64,
    /// Ciphertext
    pub ciphertext: Vec<u8>,
}

/// Media key for per-file encryption
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MediaKey {
    /// AES-256-GCM or ChaCha20-Poly1305 key
    pub key: [u8; MEDIA_KEY_SIZE],
    /// Media type hint
    pub kind: u8,
}

impl MediaKey {
    /// Generate a fresh media key
    pub fn generate(kind: u8) -> Result<Self> {
        let mut key = [0u8; MEDIA_KEY_SIZE];
        rand::rng().fill_bytes(&mut key);
        Ok(Self { key, kind })
    }

    /// Encrypt a media chunk
    pub fn encrypt_chunk(&self, chunk: &[u8], chunk_index: u64) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0u8; MEDIA_NONCE_SIZE];
        nonce[4..].copy_from_slice(&chunk_index.to_be_bytes());
        let ciphertext = cipher.encrypt(
            &nonce.into(),
            Payload { msg: chunk, aad: b"presidium-media" }
        ).map_err(|_| CryptoError::EncryptionFailed("Media encryption failed".into()))?;
        Ok(ciphertext)
    }

    /// Decrypt a media chunk
    pub fn decrypt_chunk(&self, chunk: &[u8], chunk_index: u64) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let mut nonce = [0u8; MEDIA_NONCE_SIZE];
        nonce[4..].copy_from_slice(&chunk_index.to_be_bytes());
        let plaintext = cipher.decrypt(
            &nonce.into(),
            Payload { msg: chunk, aad: b"presidium-media" }
        ).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

/// Internal identity key alias (pubkey only)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct IdentityKey {
    /// Ed25519 bytes
    pub public: Vec<u8>,
}

/// HMAC-SHA256 helper
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA256_SIZE]> {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key".into()))?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; HMAC_SHA256_SIZE];
    result.copy_from_slice(&out);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_key_roundtrip() {
        let key = MediaKey::generate(1).unwrap();
        let data = b"content block";
        let enc = key.encrypt_chunk(data, 0).unwrap();
        let dec = key.decrypt_chunk(&enc, 0).unwrap();
        assert_eq!(&dec[..], data);
    }

    #[test]
    fn test_sender_key() {
        let group = b"test-group";
        let identity = IdentityKey { public: vec![1,2,3] };
        let mut sender = SenderKeys::new(group, &identity).unwrap();
        let msg = b"group message";
        // Receiver shares the group chain key; capture it before the sender advances it
        let initial_chain = sender.chain_key;
        let enc = sender.encrypt(msg, b"aad").unwrap();
        let mut receiver = SenderKeys::new(group, &identity).unwrap();
        receiver.chain_key = initial_chain;
        // Decrypt with the message number used at encryption time
        let dec = receiver.decrypt(&enc, 0, b"aad").unwrap();
        assert_eq!(&dec[..], msg);
    }

    #[test]
    fn test_sender_key_receiver_advance_stays_in_sync() {
        let group = b"sync-group";
        let identity = IdentityKey { public: vec![4, 5, 6] };
        let mut sender = SenderKeys::new(group, &identity).unwrap();
        let initial_chain = sender.chain_key;
        let mut receiver = SenderKeys::new(group, &identity).unwrap();
        receiver.chain_key = initial_chain;

        for index in 0..3u64 {
            let enc = sender.encrypt(b"chained", b"aad").unwrap();
            let dec = receiver.decrypt(&enc, index, b"aad").unwrap();
            assert_eq!(&dec[..], b"chained");
            receiver.advance().unwrap();
        }
        assert_eq!(receiver.message_index, 3);
        assert_eq!(receiver.chain_key, sender.chain_key, "chains must be in sync");
    }
}