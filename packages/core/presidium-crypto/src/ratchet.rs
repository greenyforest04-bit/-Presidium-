//! Double Ratchet implementation (Signal Protocol)
//!
//! Provides forward secrecy and post-compromise security for message
//! encryption after the initial PQXDH key agreement.

use crate::constants::*;
use crate::error::{CryptoError, Result};
use crate::keys::{CHAIN_KEY_INFO, MESSAGE_KEY_INFO};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use chacha20poly1305::aead::{Aead, Payload};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};

/// Message key derived from a chain key
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct MessageKeys {
    /// AES/ChaCha key for message encryption
    pub key: [u8; MESSAGE_KEY_SIZE],
    /// Counter used for this message
    pub index: u64,
}

/// Chain key for a sending or receiving chain
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct ChainKey {
    key: [u8; CHAIN_KEY_SIZE],
    index: u64,
}

impl ChainKey {
    /// Create a new chain key
    pub fn new(key: [u8; CHAIN_KEY_SIZE], index: u64) -> Self {
        Self { key, index }
    }

    /// Current message index
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Get the raw key material
    pub fn as_bytes(&self) -> &[u8; CHAIN_KEY_SIZE] {
        &self.key
    }

    /// Derive the message key for the current index
    pub fn message_key(&self) -> Result<MessageKeys> {
        let digest = hmac_sha256(&self.key, MESSAGE_KEY_INFO)?;
        let mut key = [0u8; MESSAGE_KEY_SIZE];
        key.copy_from_slice(&digest[..MESSAGE_KEY_SIZE]);
        Ok(MessageKeys { key, index: self.index })
    }

    /// Create the next chain key
    pub fn next(&self) -> Result<Self> {
        let digest = hmac_sha256(&self.key, CHAIN_KEY_INFO)?;
        let mut key = [0u8; CHAIN_KEY_SIZE];
        key.copy_from_slice(&digest[..CHAIN_KEY_SIZE]);
        Ok(Self { key, index: self.index + 1 })
    }
}

/// Root key for ratchet advancement
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct RootKey {
    key: [u8; ROOT_KEY_SIZE],
}

impl RootKey {
    /// Create a new root key
    pub fn new(key: [u8; ROOT_KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Create a new root key from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ROOT_KEY_SIZE {
            return Err(CryptoError::InvalidKey("Root key must be 32 bytes".into()));
        }
        let mut key = [0u8; ROOT_KEY_SIZE];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }

    /// Get the raw root key material
    pub fn as_bytes(&self) -> &[u8; ROOT_KEY_SIZE] {
        &self.key
    }

    /// DH ratchet step: derive new root + chain keys from DH output
    pub fn ratchet_step(&self, dh_output: &[u8; X25519_SHARED_SECRET_SIZE]) -> Result<(Self, ChainKey)> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.key), dh_output);
        let mut new_root = [0u8; ROOT_KEY_SIZE];
        let mut new_chain = [0u8; CHAIN_KEY_SIZE];
        hkdf.expand(b"presidium-ratchet-root", &mut new_root)
            .map_err(|_| CryptoError::KeyDerivationFailed("Root key derivation failed".into()))?;
        hkdf.expand(b"presidium-ratchet-chain", &mut new_chain)
            .map_err(|_| CryptoError::KeyDerivationFailed("Chain key derivation failed".into()))?;
        Ok((RootKey::new(new_root), ChainKey::new(new_chain, 0)))
    }
}

/// Header of an encrypted ratchet message
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessageHeader {
    /// DH public key of the ratchet state that generated the message
    pub dh_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Current message number in this sending chain
    pub message_number: u64,
    /// Previous message number in the receiving chain
    pub previous_message_number: u64,
}

/// State of a single ratchet chain (sending or receiving)
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetChain {
    /// The DH key pair (our ratchet key when sending)
    pub our_ratchet_key: Option<X25519StaticSecret>,
    /// The peer's ratchet public key
    pub their_ratchet_public: Option<[u8; X25519_PUBLIC_KEY_SIZE]>,
    /// Current chain key
    pub chain_key: Option<ChainKey>,
    /// Stored message keys for skipped messages (index -> key)
    pub skipped_message_keys: Vec<(u64, [u8; MESSAGE_KEY_SIZE])>,
}

/// Zeroize-friendly wrapper for X25519 static secret serialization
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct XStaticDHBytes {
    /// Raw 32 bytes of the X25519 secret key
    pub bytes: [u8; X25519_PRIVATE_KEY_SIZE],
}

/// Main Double Ratchet state machine
#[derive(Clone, Serialize, Deserialize)]
pub struct DoubleRatchet {
    /// Root key for ratchet
    pub root_key: RootKey,
    /// Sending chain state
    pub sending_chain: RatchetChain,
    /// Receiving chain state
    pub receiving_chain: RatchetChain,
    /// Session identifier (conversation ID)
    pub session_id: String,
    /// Associated data for encryption (e.g., user identifiers)
    pub associated_data: Vec<u8>,
}

/// HKDF info strings
pub const DHX_SHARED_SECRET_SIZE: usize = X25519_SHARED_SECRET_SIZE;

impl DoubleRatchet {
    /// Initialize a new session as the initiator
    pub fn init(
        session_id: String,
        root_key: RootKey,
        our_dh_key: X25519StaticSecret,
        peer_dh_public: X25519PublicKey,
        associated_data: Vec<u8>,
    ) -> Result<Self> {
        // Derive the initial sending chain from the real DH with the peer
        let shared = our_dh_key.diffie_hellman(&peer_dh_public);
        let (new_root, chain) = root_key.ratchet_step(shared.as_bytes())?;
        Ok(Self {
            root_key: new_root,
            sending_chain: RatchetChain {
                our_ratchet_key: Some(our_dh_key),
                their_ratchet_public: Some(peer_dh_public.to_bytes()),
                chain_key: Some(chain),
                skipped_message_keys: Vec::new(),
            },
            receiving_chain: RatchetChain {
                our_ratchet_key: None,
                their_ratchet_public: Some(peer_dh_public.to_bytes()),
                chain_key: None,
                skipped_message_keys: Vec::new(),
            },
            session_id,
            associated_data,
        })
    }

    /// Initialize a session as the responder
    pub fn init_as_responder(
        session_id: String,
        root_key: RootKey,
        our_ratchet_key: X25519StaticSecret,
        associated_data: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            root_key,
            sending_chain: RatchetChain {
                our_ratchet_key: Some(our_ratchet_key),
                their_ratchet_public: None,
                chain_key: None,
                skipped_message_keys: Vec::new(),
            },
            receiving_chain: RatchetChain {
                our_ratchet_key: None,
                their_ratchet_public: None,
                chain_key: None,
                skipped_message_keys: Vec::new(),
            },
            session_id,
            associated_data,
        })
    }

    /// Encrypt a message using the Double Ratchet
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, RatchetMessageHeader)> {
        // Ensure we have a chain key for sending; derive it from the real DH
        // with the peer's ratchet public key when it is not yet established.
        if self.sending_chain.chain_key.is_none() {
            let our_key = self
                .sending_chain
                .our_ratchet_key
                .as_ref()
                .ok_or_else(|| CryptoError::RatchetError("No sending ratchet key".into()))?;
            let their_bytes = self
                .sending_chain
                .their_ratchet_public
                .ok_or_else(|| CryptoError::RatchetError("No peer ratchet key".into()))?;
            let shared = our_key.diffie_hellman(&X25519PublicKey::from(their_bytes));
            let (new_root, chain) = self.root_key.ratchet_step(shared.as_bytes())?;
            self.root_key = new_root;
            self.sending_chain.chain_key = Some(chain);
        }

        let chain = self.sending_chain.chain_key.as_mut()
            .ok_or_else(|| CryptoError::RatchetError("No sending chain".into()))?;
        let message_key = chain.message_key()?;
        *chain = chain.next()?;

        // Build header carrying our own ratchet public key
        let dh_public_key = match &self.sending_chain.our_ratchet_key {
            Some(key) => X25519PublicKey::from(key).to_bytes(),
            None => [0u8; X25519_PUBLIC_KEY_SIZE],
        };
        let header = RatchetMessageHeader {
            dh_public_key,
            message_number: message_key.index,
            previous_message_number: 0,
        };

        // Encrypt with message key
        let cipher = ChaCha20Poly1305::new((&message_key.key).into());
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        nonce[4..].copy_from_slice(&message_key.index.to_le_bytes());
        
        let serialized_header = serde_json::to_vec(&header)?;
        let mut data = Vec::with_capacity(serialized_header.len() + plaintext.len() + CHACHA20_POLY1305_TAG_SIZE);
        data.extend_from_slice(&serialized_header);
        data.extend_from_slice(plaintext);
        
        let ciphertext = cipher.encrypt(
            &nonce.into(),
            Payload { msg: plaintext, aad: &serialized_header }
        ).map_err(|_| CryptoError::EncryptionFailed("Ratchet encryption failed".into()))?;

        Ok((ciphertext, header))
    }

    /// Decrypt a message using the Double Ratchet
    pub fn decrypt(&mut self, ciphertext: &[u8], header: &RatchetMessageHeader) -> Result<Vec<u8>> {
        // Handle skipped message keys
        // In production, this would check and use stored keys
        if let Some((_, key)) = self.receiving_chain.skipped_message_keys
            .iter()
            .find(|(idx, _)| *idx == header.message_number) {
            let cipher = ChaCha20Poly1305::new(key.into());
            let serialized_header = serde_json::to_vec(header)?;
            let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
            nonce[4..].copy_from_slice(&header.message_number.to_le_bytes());
            let plaintext = cipher.decrypt(
                &nonce.into(),
                Payload { msg: ciphertext, aad: &serialized_header }
            ).map_err(|_| CryptoError::DecryptionFailed)?;
            return Ok(plaintext);
        }

        // Ensure receiving chain has a chain key
        if self.receiving_chain.chain_key.is_none() {
            return Err(CryptoError::RatchetError("No receiving chain established".into()));
        }

        let chain = self.receiving_chain.chain_key.as_mut()
            .ok_or_else(|| CryptoError::RatchetError("No receiving chain".into()))?;

        // Advance chain to message index
        while chain.index() < header.message_number {
            let msg_key = chain.message_key()?;
            self.receiving_chain.skipped_message_keys.push((msg_key.index, msg_key.key));
            if self.receiving_chain.skipped_message_keys.len() > MAX_SKIP_MESSAGES {
                return Err(CryptoError::RatchetError("Too many skipped messages".into()));
            }
            *chain = chain.next()?;
        }

        let message_key = chain.message_key()?;
        *chain = chain.next()?;

        // Decrypt
        let cipher = ChaCha20Poly1305::new((&message_key.key).into());
        let serialized_header = serde_json::to_vec(header)?;
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
        nonce[4..].copy_from_slice(&header.message_number.to_le_bytes());
        let plaintext = cipher.decrypt(
            &nonce.into(),
            Payload { msg: ciphertext, aad: &serialized_header }
        ).map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(plaintext)
    }

    /// The DH ratchet step: update our ratchet key pair
    pub fn dh_ratchet(&mut self, peer_ratchet_public: X25519PublicKey) -> Result<()> {
        // Use the ratchet key from either chain (initiator: receiving, responder: sending)
        let our_key = self
            .receiving_chain
            .our_ratchet_key
            .clone()
            .or_else(|| self.sending_chain.our_ratchet_key.clone())
            .ok_or_else(|| CryptoError::RatchetError("No ratchet key available".into()))?;
        let shared = our_key.diffie_hellman(&peer_ratchet_public);

        // Advance root key
        let (new_root, new_chain) = self.root_key.ratchet_step(shared.as_bytes())?;
        self.root_key = new_root;
        self.sending_chain.their_ratchet_public = Some(peer_ratchet_public.to_bytes());

        if self.receiving_chain.our_ratchet_key.is_some() {
            // Initiator receiving a response: rotate our key into the sending chain
            self.sending_chain.our_ratchet_key = self.receiving_chain.our_ratchet_key.take();
            self.sending_chain.chain_key = Some(new_chain);
        } else {
            // Responder: the derived chain becomes our receiving chain
            self.receiving_chain.chain_key = Some(new_chain);
        }

        Ok(())
    }
}

/// Compute HMAC-SHA256 with the given key
fn hmac_sha256(key: &[u8], info: &[u8]) -> Result<[u8; HMAC_SHA256_SIZE]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| CryptoError::KeyDerivationFailed("Invalid HMAC key".into()))?;
    mac.update(info);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; HMAC_SHA256_SIZE];
    output.copy_from_slice(&result);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_next() {
        let key = [0x01u8; CHAIN_KEY_SIZE];
        let chain = ChainKey::new(key, 0);
        assert_eq!(chain.index(), 0);
        let next = chain.next().unwrap();
        assert_eq!(next.index(), 1);
        // Message keys should differ between chain steps
        let mk1 = chain.message_key().unwrap();
        let mk2 = next.message_key().unwrap();
        assert_ne!(mk1.key, mk2.key);
    }

    #[test]
    fn test_ratchet_encrypt_decrypt() {
        // Create session keys
        let alice_ratchet = X25519StaticSecret::random();
        let alice_public = X25519PublicKey::from(&alice_ratchet);
        let bob_ratchet = X25519StaticSecret::random();
        let bob_public = X25519PublicKey::from(&bob_ratchet);

        let root_key = RootKey::new([0x42u8; ROOT_KEY_SIZE]);

        let mut alice = DoubleRatchet::init(
            "test-session".into(),
            root_key.clone(),
            alice_ratchet,
            bob_public,
            b"aad".to_vec(),
        ).unwrap();

        let mut bob = DoubleRatchet::init_as_responder(
            "test-session".into(),
            root_key,
            bob_ratchet,
            b"aad".to_vec(),
        ).unwrap();

        // Alice encrypts, Bob decrypts
        let (ciphertext, header) = alice.encrypt(b"Hello, Bob!").unwrap();
        // Bob performs DH ratchet on receiving Alice's public key
        bob.dh_ratchet(alice_public.clone()).unwrap();
        let plaintext = bob.decrypt(&ciphertext, &header).unwrap();
        assert_eq!(&plaintext[..], b"Hello, Bob!");
    }
}