//! Network identity: libp2p key material for a Presidium node.

use libp2p::identity::Keypair;
use libp2p::PeerId;

use crate::error::{NetworkError, Result};

/// A libp2p identity bound to a Presidium device.
#[derive(Clone)]
pub struct NetworkIdentity {
    keypair: Keypair,
}

impl std::fmt::Debug for NetworkIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkIdentity")
            .field("peer_id", &self.peer_id())
            .finish()
    }
}

impl NetworkIdentity {
    /// Generate a fresh random identity (tests, ad-hoc nodes).
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }

    /// Build an identity deterministically from a 32-byte secret seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != 32 {
            return Err(NetworkError::InvalidKey(format!(
                "seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let keypair = Keypair::ed25519_from_bytes(seed.to_vec())
            .map_err(|e| NetworkError::InvalidKey(e.to_string()))?;
        Ok(Self { keypair })
    }

    /// Derive a deterministic identity from a 16-byte device id.
    ///
    /// The device id is hashed with SHA-256 (domain-separated) into the
    /// 32-byte ed25519 seed, so the same device always gets the same peer id.
    pub fn from_device_id(device_id: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"presidium-network-v1");
        hasher.update(device_id);
        let seed: [u8; 32] = hasher.finalize().into();
        // SHA-256 output is always a valid 32-byte seed.
        Self::from_seed(&seed).expect("32-byte seed is valid")
    }

    /// The underlying libp2p keypair.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// The libp2p peer id of this node.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let a = NetworkIdentity::from_seed(&seed).unwrap();
        let b = NetworkIdentity::from_seed(&seed).unwrap();
        assert_eq!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn different_seeds_differ() {
        let a = NetworkIdentity::from_seed(&[1u8; 32]).unwrap();
        let b = NetworkIdentity::from_seed(&[2u8; 32]).unwrap();
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn seed_must_be_32_bytes() {
        assert!(NetworkIdentity::from_seed(&[0u8; 31]).is_err());
        assert!(NetworkIdentity::from_seed(&[0u8; 33]).is_err());
    }

    #[test]
    fn device_id_is_deterministic() {
        let a = NetworkIdentity::from_device_id(&[3u8; 16]);
        let b = NetworkIdentity::from_device_id(&[3u8; 16]);
        assert_eq!(a.peer_id(), b.peer_id());
        assert_ne!(a.peer_id(), NetworkIdentity::from_device_id(&[4u8; 16]).peer_id());
    }
}
