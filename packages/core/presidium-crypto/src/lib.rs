//! Presidium Crypto - PQXDH + Double Ratchet Implementation
//! 
//! This crate implements the Signal Protocol v2 (PQXDH) with post-quantum
//! cryptography: ML-KEM-1024 for key encapsulation and ML-DSA-87 for signatures.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod error;
pub mod identity;
pub mod pqxdh;
pub mod ratchet;
pub mod keys;
pub mod crypto_box;
pub mod serialization;
pub mod constants;

pub use error::{CryptoError, Result};
pub use identity::{
    IdentityKeyPair, IdentityPublicKey, MlDsa87PrivateKey, MlDsa87PublicKey,
    PreKeyBundle, SignedPreKey, OneTimePreKey, HybridSignature,
    HybridKemPublicKey, HybridKemPrivateKey,
};
pub use pqxdh::{
    pqxdh_initiator, pqxdh_responder,
    PqxdhOutput, PqxdhPrekeyMessage, PqxdhInitiatorKeys, PqxdhResponderKeys,
};
pub use ratchet::{
    DoubleRatchet, RatchetChain, ChainKey, MessageKeys,
    RootKey, RatchetMessageHeader,
};
pub use keys::{
    SessionKeys, SenderKeys, SenderKeyMessage, MediaKey,
    HKDF_INFO, CHAIN_KEY_INFO, ROOT_KEY_INFO, MESSAGE_KEY_INFO,
};
pub use crypto_box::{crypto_box_seal, crypto_box_open, CryptoBox};
pub use serialization::{Serializable, serialize, deserialize};
pub use constants::*;

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();