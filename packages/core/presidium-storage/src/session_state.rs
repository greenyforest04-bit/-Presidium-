//! Persisted session state: PQXDH-derived keys plus a Double Ratchet snapshot.

use presidium_crypto::keys::SessionKeys;
use presidium_crypto::ratchet::{ChainKey, DoubleRatchet, RatchetChain, RootKey};
use presidium_crypto::constants::{CHAIN_KEY_SIZE, MESSAGE_KEY_SIZE, ROOT_KEY_SIZE, X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE};
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::error::{Result, StorageError};

/// Serialized state of one conversation session.
///
/// `session_keys` round-trips via serde; the Double Ratchet is stored as a
/// flat snapshot because `x25519` secrets cannot be serialized directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub is_initiator: bool,
    pub session_keys: SessionKeys,
    pub ratchet: Option<RatchetSnapshot>,
    /// Unix timestamp (ms) of the last use.
    pub last_used: i64,
}

/// Flat, serializable snapshot of a [`DoubleRatchet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetSnapshot {
    pub root_key: [u8; ROOT_KEY_SIZE],
    pub sending_chain: ChainSnapshot,
    pub receiving_chain: ChainSnapshot,
}

/// Flat, serializable snapshot of a [`RatchetChain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSnapshot {
    pub our_ratchet_key: Option<[u8; X25519_PRIVATE_KEY_SIZE]>,
    pub their_ratchet_public: Option<[u8; X25519_PUBLIC_KEY_SIZE]>,
    pub chain_key: Option<[u8; CHAIN_KEY_SIZE]>,
    pub chain_index: u64,
    pub skipped_message_keys: Vec<(u64, [u8; MESSAGE_KEY_SIZE])>,
}

impl ChainSnapshot {
    fn from_chain(chain: &RatchetChain) -> Self {
        Self {
            our_ratchet_key: chain.our_ratchet_key.as_ref().map(StaticSecret::to_bytes),
            their_ratchet_public: chain.their_ratchet_public,
            chain_key: chain.chain_key.as_ref().map(|ck| *ck.as_bytes()),
            chain_index: chain.chain_key.as_ref().map_or(0, ChainKey::index),
            skipped_message_keys: chain.skipped_message_keys.clone(),
        }
    }

    fn to_chain(&self) -> Result<RatchetChain> {
        let chain_key = match (self.chain_key, self.chain_index) {
            (Some(key), index) => Some(ChainKey::new(key, index)),
            (None, 0) => None,
            (None, _) => {
                return Err(StorageError::InvalidData(
                    "chain snapshot has an index but no chain key".into(),
                ))
            }
        };
        Ok(RatchetChain {
            our_ratchet_key: self.our_ratchet_key.map(StaticSecret::from),
            their_ratchet_public: self.their_ratchet_public,
            chain_key,
            skipped_message_keys: self.skipped_message_keys.clone(),
        })
    }
}

impl RatchetSnapshot {
    /// Capture the state of a live ratchet.
    pub fn from_ratchet(ratchet: &DoubleRatchet) -> Self {
        Self {
            root_key: *ratchet.root_key.as_bytes(),
            sending_chain: ChainSnapshot::from_chain(&ratchet.sending_chain),
            receiving_chain: ChainSnapshot::from_chain(&ratchet.receiving_chain),
        }
    }

    /// Rebuild a live ratchet from the snapshot.
    pub fn to_ratchet(&self, session_id: String, associated_data: Vec<u8>) -> Result<DoubleRatchet> {
        Ok(DoubleRatchet {
            root_key: RootKey::new(self.root_key),
            sending_chain: self.sending_chain.to_chain()?,
            receiving_chain: self.receiving_chain.to_chain()?,
            session_id,
            associated_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::PublicKey;

    fn sample_ratchet() -> DoubleRatchet {
        DoubleRatchet::init(
            "conv-1".into(),
            RootKey::new([1u8; ROOT_KEY_SIZE]),
            StaticSecret::from([2u8; X25519_PRIVATE_KEY_SIZE]),
            PublicKey::from(&StaticSecret::from([3u8; X25519_PRIVATE_KEY_SIZE])),
            b"alice|bob".to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let mut ratchet = sample_ratchet();
        let (_ct, _header) = ratchet.encrypt(b"hello").unwrap();

        let snapshot = RatchetSnapshot::from_ratchet(&ratchet);
        let rebuilt = snapshot
            .to_ratchet("conv-1".into(), b"alice|bob".to_vec())
            .unwrap();
        let mut rebuilt = rebuilt;

        assert_eq!(snapshot, RatchetSnapshot::from_ratchet(&rebuilt));

        let (ct_a, hdr_a) = ratchet.encrypt(b"first").unwrap();
        let (ct_b, hdr_b) = rebuilt.encrypt(b"first").unwrap();
        assert_eq!((ct_a, hdr_a), (ct_b, hdr_b), "rebuilt ratchet must encrypt identically");
    }
}
