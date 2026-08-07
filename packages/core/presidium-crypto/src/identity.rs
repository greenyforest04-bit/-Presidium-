//! Identity keys and prekey management.
//!
//! Presidium uses hybrid post-quantum cryptography:
//! - **Ed25519 + ML-DSA-87** for signatures (hybrid signature).
//! - **X25519 + ML-KEM-1024** for key encapsulation (hybrid KEM).

use crate::constants::*;
use crate::error::{CryptoError, Result};

use ed25519_dalek::Signer as _;
use ed25519_dalek::Verifier as _;
use ed25519_dalek::{
    Signature as Ed25519Signature,
    SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hkdf::Hkdf;
use ml_dsa::{
    MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey,
};
use ml_kem::{
    Decapsulate as _, Encapsulate as _, EncapsulationKey as MlKemEncapsulationKey,
    DecapsulationKey as MlKemDecapsulationKey, Key as MlKemKey, KeyExport as _, Kem as _,
    MlKem1024,
};
use rand::{rng, Rng};
use serde::{
    de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-DSA-87 private key wrapper around the canonical 32-byte seed.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87PrivateKey {
    key: [u8; ML_DSA_87_PRIVATE_KEY_SIZE],
}

/// ML-DSA-87 public key wrapper.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87PublicKey {
    key: [u8; ML_DSA_87_PUBLIC_KEY_SIZE],
}

/// Hybrid identity key pair: Ed25519 + ML-DSA-87.
#[derive(Clone)]
pub struct IdentityKeyPair {
    classical: Ed25519SigningKey,
    pq: MlDsa87PrivateKey,
}

/// Hybrid identity public key: Ed25519 + ML-DSA-87.
#[derive(Clone, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct IdentityPublicKey {
    /// Ed25519 public key bytes
    pub classical: [u8; ED25519_PUBLIC_KEY_SIZE],
    /// ML-DSA-87 public key bytes
    pub pq: [u8; ML_DSA_87_PUBLIC_KEY_SIZE],
}

/// Hybrid signature: Ed25519 + ML-DSA-87.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HybridSignature {
    /// Ed25519 signature bytes
    pub classical: [u8; ED25519_SIGNATURE_SIZE],
    /// ML-DSA-87 encoded signature (`ML_DSA_87_SIGNATURE_SIZE` bytes).
    pub pq: Vec<u8>,
}

/// Hybrid KEM public key: X25519 + ML-KEM-1024.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemPublicKey {
    /// X25519 public key bytes
    pub classical: [u8; X25519_PUBLIC_KEY_SIZE],
    /// ML-KEM-1024 encapsulation key bytes
    pub pq: [u8; ML_KEM_1024_PUBLIC_KEY_SIZE],
}

/// Hybrid KEM private key: X25519 secret + ML-KEM-1024 seed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemPrivateKey {
    /// X25519 secret key bytes
    pub classical: [u8; X25519_PRIVATE_KEY_SIZE],
    /// ML-KEM-1024 decapsulation key seed (`ML_KEM_1024_PRIVATE_KEY_SIZE` bytes).
    pub pq: [u8; ML_KEM_1024_PRIVATE_KEY_SIZE],
}

impl fmt::Debug for HybridKemPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKemPrivateKey")
            .field("classical", &"<redacted>")
            .field("pq", &"<redacted>")
            .finish()
    }
}

/// Signed prekey for PQXDH.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    /// Prekey identifier
    pub key_id: u32,
    /// Hybrid KEM public key
    pub public_key: HybridKemPublicKey,
    /// Signature of the public key by the identity key
    pub signature: HybridSignature,
    /// Creation timestamp (Unix seconds)
    pub timestamp: u64,
}

/// One-time prekey for PQXDH.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OneTimePreKey {
    /// Prekey identifier
    pub key_id: u32,
    /// Hybrid KEM public key
    pub public_key: HybridKemPublicKey,
}

/// Prekey bundle for PQXDH key agreement.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyBundle {
    /// Owner's hybrid identity public key
    pub identity_key: IdentityPublicKey,
    /// Deterministic identity-derived hybrid KEM public key (X25519 + ML-KEM-1024)
    pub identity_kem_public: HybridKemPublicKey,
    /// Owner's signed prekey
    pub signed_prekey: SignedPreKey,
    /// Owner's one-time prekeys
    pub one_time_prekeys: Vec<OneTimePreKey>,
    /// Bundle signature by the identity key
    pub bundle_signature: HybridSignature,
}

/// Build the ML-DSA-87 verifying key from its encoded bytes.
fn ml_dsa_verifying_key(bytes: &[u8; ML_DSA_87_PUBLIC_KEY_SIZE]) -> MlDsaVerifyingKey<MlDsa87> {
    let encoded: ml_dsa::EncodedVerifyingKey<MlDsa87> =
        ml_dsa::EncodedVerifyingKey::<MlDsa87>::from(*bytes);
    MlDsaVerifyingKey::decode(&encoded)
}

/// Decode a serialized ML-DSA-87 signature.
fn ml_dsa_signature(bytes: &[u8]) -> Result<MlDsaSignature<MlDsa87>> {
    let arr: [u8; ML_DSA_87_SIGNATURE_SIZE] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidSignature)?;
    let encoded: ml_dsa::EncodedSignature<MlDsa87> =
        ml_dsa::EncodedSignature::<MlDsa87>::from(arr);
    MlDsaSignature::decode(&encoded).ok_or(CryptoError::InvalidSignature)
}

impl IdentityKeyPair {
    /// Generate a new hybrid identity key pair.
    pub fn generate() -> Result<Self> {
        let mut rng = rng();
        let classical = Ed25519SigningKey::generate(&mut rng);
        let mut seed = [0u8; ML_DSA_87_PRIVATE_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        Ok(Self {
            classical,
            pq: MlDsa87PrivateKey { key: seed },
        })
    }

    /// Reconstruct an identity from the stored seeds.
    ///
    /// `classical_seed` is the 32-byte Ed25519 seed and `pq_seed` the
    /// 32-byte ML-DSA-87 seed, exactly what an `IdentityRecord` persists.
    pub fn from_seed(classical_seed: &[u8], pq_seed: &[u8]) -> Result<Self> {
        let classical_bytes: [u8; ED25519_PRIVATE_KEY_SIZE] = classical_seed
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("classical seed must be 32 bytes".into()))?;
        let pq_bytes: [u8; ML_DSA_87_PRIVATE_KEY_SIZE] = pq_seed
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("pq seed must be 32 bytes".into()))?;
        Ok(Self {
            classical: Ed25519SigningKey::from_bytes(&classical_bytes),
            pq: MlDsa87PrivateKey { key: pq_bytes },
        })
    }

    /// Get the public key.
    pub fn public(&self) -> IdentityPublicKey {
        let sk = self.pq_signing_key();
        let vk = sk.as_ref();
        IdentityPublicKey {
            classical: self.classical.verifying_key().to_bytes(),
            pq: vk.clone().encode().into(),
        }
    }

    /// Sign data with both classical and PQ keys.
    pub fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignature> {
        let classical_sig = self.classical.sign(message);
        let pq_sig = self.pq_signing_key().sign(message);
        Ok(HybridSignature {
            classical: classical_sig.to_bytes(),
            pq: pq_sig.encode().as_slice().to_vec(),
        })
    }

    /// Verify a hybrid signature against a public key.
    pub fn verify_hybrid(
        public: &IdentityPublicKey,
        message: &[u8],
        sig: &HybridSignature,
    ) -> Result<()> {
        let verifying_key = Ed25519VerifyingKey::from_bytes(&public.classical)
            .map_err(|_| CryptoError::InvalidKey("Invalid Ed25519 public key".into()))?;
        verifying_key
            .verify(message, &Ed25519Signature::from_bytes(&sig.classical))
            .map_err(|_| CryptoError::InvalidSignature)?;

        let verifying_key = ml_dsa_verifying_key(&public.pq);
        let pq_sig = ml_dsa_signature(&sig.pq)?;
        verifying_key
            .verify(message, &pq_sig)
            .map_err(|_| CryptoError::InvalidSignature)?;

        Ok(())
    }

    /// The raw seeds, as persisted in an `IdentityRecord`.
    ///
    /// Returns the Ed25519 seed and the ML-DSA-87 seed; pass them to
    /// [`Self::from_seed`] to rebuild the identity on the next boot.
    pub fn seeds(&self) -> ([u8; ED25519_PRIVATE_KEY_SIZE], [u8; ML_DSA_87_PRIVATE_KEY_SIZE]) {
        (self.classical_seed(), self.pq_seed())
    }

    /// Classical (Ed25519) seed, usable to derive the identity X25519 secret.
    pub(crate) fn classical_seed(&self) -> [u8; ED25519_PRIVATE_KEY_SIZE] {
        self.classical.to_bytes()
    }

    /// Post-quantum (ML-DSA-87) seed.
    pub(crate) fn pq_seed(&self) -> [u8; ML_DSA_87_PRIVATE_KEY_SIZE] {
        self.pq.key
    }

    /// Reconstruct the ML-DSA-87 signing key from the stored seed.
    pub(crate) fn pq_signing_key(&self) -> MlDsaSigningKey<MlDsa87> {
        MlDsaSigningKey::from_seed(&ml_dsa::Seed::from(self.pq.key))
    }

    /// Deterministic identity-derived hybrid KEM private key (X25519 + ML-KEM-1024).
    ///
    /// Both sides derive identical key material from the identity, so no
    /// public-from-public tricks are needed: the public counterpart is
    /// exchanged explicitly in pre-key messages and bundles.
    pub(crate) fn kem_secret(&self) -> Result<HybridKemPrivateKey> {
        let classical = X25519StaticSecret::from(self.classical_seed()).to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(b"presidium-identity-kem"), self.pq_seed().as_slice());
        let mut pq = [0u8; ML_KEM_1024_PRIVATE_KEY_SIZE];
        hk.expand(b"identity-pq-seed", &mut pq)
            .map_err(|_| CryptoError::KeyDerivationFailed("Identity KEM seed derivation failed".into()))?;
        Ok(HybridKemPrivateKey { classical, pq })
    }

    /// Deterministic identity-derived hybrid KEM public key.
    pub(crate) fn kem_public(&self) -> Result<HybridKemPublicKey> {
        Ok(self.kem_secret()?.public_key())
    }
}

impl MlDsa87PrivateKey {
    /// Reconstruct the ML-DSA-87 signing key from the stored seed.
    pub(crate) fn signing_key(&self) -> MlDsaSigningKey<MlDsa87> {
        MlDsaSigningKey::from_seed(&ml_dsa::Seed::from(self.key))
    }

    /// Derive the corresponding public key.
    pub(crate) fn public_key(&self) -> MlDsa87PublicKey {
        MlDsa87PublicKey {
            key: self.signing_key().as_ref().clone().encode().into(),
        }
    }
}

impl MlDsa87PublicKey {
    /// Parse a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; ML_DSA_87_PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-87 public key size".into()))?;
        Ok(Self { key })
    }

    /// The raw public key bytes.
    pub fn as_bytes(&self) -> &[u8; ML_DSA_87_PUBLIC_KEY_SIZE] {
        &self.key
    }
}

impl HybridKemPublicKey {
    /// Generate a new hybrid KEM key pair.
    pub fn generate() -> Result<(Self, HybridKemPrivateKey)> {
        let mut rng = rng();
        let classical_secret = X25519StaticSecret::random();
        let classical_public = X25519PublicKey::from(&classical_secret);

        let (dk, ek) = MlKem1024::generate_keypair_from_rng(&mut rng);
        let pq_seed: ml_kem::Seed = dk.to_seed().ok_or_else(|| {
            CryptoError::KeyDerivationFailed("ML-KEM-1024 seed unavailable".into())
        })?;

        Ok((
            Self {
                classical: classical_public.to_bytes(),
                pq: ek.to_bytes().into(),
            },
            HybridKemPrivateKey {
                classical: classical_secret.to_bytes(),
                pq: pq_seed.into(),
            },
        ))
    }

    /// Parse a hybrid KEM public key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (classical, pq) = bytes
            .split_at_checked(X25519_PUBLIC_KEY_SIZE)
            .ok_or_else(|| CryptoError::InvalidKey("Hybrid KEM public key too short".into()))?;
        let classical: [u8; X25519_PUBLIC_KEY_SIZE] = classical
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid X25519 public key size".into()))?;
        let pq: [u8; ML_KEM_1024_PUBLIC_KEY_SIZE] = pq
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Invalid ML-KEM-1024 public key size".into()))?;
        Ok(Self { classical, pq })
    }

    /// Concatenated encoding: X25519 public key followed by ML-KEM-1024 public key.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(X25519_PUBLIC_KEY_SIZE + ML_KEM_1024_PUBLIC_KEY_SIZE);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pq);
        out
    }
}

impl HybridKemPrivateKey {
    /// Reconstruct the X25519 static secret from the stored bytes.
    fn x25519_secret(&self) -> X25519StaticSecret {
        X25519StaticSecret::from(self.classical)
    }

    /// Reconstruct the ML-KEM-1024 decapsulation key from the stored seed.
    fn kem_decapsulation_key(&self) -> MlKemDecapsulationKey<MlKem1024> {
        MlKemDecapsulationKey::from_seed(ml_kem::Seed::from(self.pq))
    }

    /// The matching public key.
    pub fn public_key(&self) -> HybridKemPublicKey {
        let classical = X25519PublicKey::from(&self.x25519_secret()).to_bytes();
        let dk = self.kem_decapsulation_key();
        let ek = dk.encapsulation_key();
        HybridKemPublicKey {
            classical,
            pq: ek.to_bytes().into(),
        }
    }

    /// Perform hybrid key encapsulation toward a peer public key.
    ///
    /// Combines X25519 DH and ML-KEM-1024 encapsulation via HKDF-SHA256.
    /// Returns `(ciphertext, shared_secret)`.
    pub fn encapsulate(&self, peer_public: &HybridKemPublicKey) -> Result<(Vec<u8>, [u8; 32])> {
        let mut rng = rng();
        let peer_classical = X25519PublicKey::from(peer_public.classical);
        let classical_shared = self.x25519_secret().diffie_hellman(&peer_classical);

        let key: MlKemKey<MlKemEncapsulationKey<MlKem1024>> =
            MlKemKey::<MlKemEncapsulationKey<MlKem1024>>::try_from(&peer_public.pq[..])
                .map_err(|_| CryptoError::InvalidKey("Invalid ML-KEM-1024 public key".into()))?;
        let ek = MlKemEncapsulationKey::<MlKem1024>::new(&key)
            .map_err(|_| CryptoError::InvalidKey("Invalid ML-KEM-1024 public key".into()))?;
        let (ciphertext, pq_shared) = ek.encapsulate_with_rng(&mut rng);

        let mut ikm = Vec::with_capacity(X25519_SHARED_SECRET_SIZE + ML_KEM_1024_SHARED_SECRET_SIZE);
        ikm.extend_from_slice(classical_shared.as_bytes());
        ikm.extend_from_slice(pq_shared.as_slice());

        let mut shared_secret = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(b"presidium-pqxdh-shared", &mut shared_secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".into()))?;

        Ok((ciphertext.as_slice().to_vec(), shared_secret))
    }

    /// Perform hybrid key decapsulation of a peer ciphertext.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
        peer_public: &HybridKemPublicKey,
    ) -> Result<[u8; 32]> {
        let peer_classical = X25519PublicKey::from(peer_public.classical);
        let classical_shared = self.x25519_secret().diffie_hellman(&peer_classical);

        let ct: ml_kem::Ciphertext<MlKem1024> = ml_kem::Ciphertext::<MlKem1024>::try_from(ciphertext)
            .map_err(|_| CryptoError::InvalidParameter("Invalid ciphertext size".into()))?;
        let pq_shared = self.kem_decapsulation_key().decapsulate(&ct);

        let mut ikm = Vec::with_capacity(X25519_SHARED_SECRET_SIZE + ML_KEM_1024_SHARED_SECRET_SIZE);
        ikm.extend_from_slice(classical_shared.as_bytes());
        ikm.extend_from_slice(pq_shared.as_slice());

        let mut shared_secret = [0u8; 32];
        Hkdf::<Sha256>::new(None, &ikm)
            .expand(b"presidium-pqxdh-shared", &mut shared_secret)
            .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".into()))?;

        Ok(shared_secret)
    }
}

impl PreKeyBundle {
    /// Create a new prekey bundle signed by the identity key.
    pub fn new(
        identity: &IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekeys: Vec<OneTimePreKey>,
    ) -> Result<Self> {
        let identity_kem_public = identity.kem_public()?;
        let bundle_bytes = bundle_bytes(
            &identity.public(),
            &identity_kem_public,
            &signed_prekey,
            &one_time_prekeys,
        );
        let bundle_signature = identity.sign_hybrid(&bundle_bytes)?;

        Ok(Self {
            identity_key: identity.public(),
            identity_kem_public,
            signed_prekey,
            one_time_prekeys,
            bundle_signature,
        })
    }

    /// Verify the prekey bundle signature.
    pub fn verify(&self) -> Result<()> {
        let bundle_bytes = bundle_bytes(
            &self.identity_key,
            &self.identity_kem_public,
            &self.signed_prekey,
            &self.one_time_prekeys,
        );
        IdentityKeyPair::verify_hybrid(&self.identity_key, &bundle_bytes, &self.bundle_signature)
    }
}

/// Deterministic canonical bytes signed by the identity key.
fn bundle_bytes(
    identity: &IdentityPublicKey,
    identity_kem_public: &HybridKemPublicKey,
    signed_prekey: &SignedPreKey,
    one_time_prekeys: &[OneTimePreKey],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&identity.classical);
    bytes.extend_from_slice(&identity.pq);
    bytes.extend_from_slice(&identity_kem_public.classical);
    bytes.extend_from_slice(&identity_kem_public.pq);
    bytes.extend_from_slice(&signed_prekey.key_id.to_le_bytes());
    bytes.extend_from_slice(&signed_prekey.public_key.classical);
    bytes.extend_from_slice(&signed_prekey.public_key.pq);
    bytes.extend_from_slice(&signed_prekey.timestamp.to_le_bytes());
    for otpk in one_time_prekeys {
        bytes.extend_from_slice(&otpk.key_id.to_le_bytes());
        bytes.extend_from_slice(&otpk.public_key.classical);
        bytes.extend_from_slice(&otpk.public_key.pq);
    }
    bytes
}

impl fmt::Debug for IdentityKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeyPair")
            .field(
                "classical_pub",
                &hex::encode(self.classical.verifying_key().to_bytes()),
            )
            .field("pq_pub", &hex::encode(self.pq.public_key().key))
            .finish()
    }
}

impl fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityPublicKey")
            .field("classical", &hex::encode(self.classical))
            .field("pq", &hex::encode(self.pq))
            .finish()
    }
}

impl Serialize for IdentityPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IdentityPublicKey", 2)?;
        state.serialize_field("classical", &self.classical)?;
        state.serialize_field("pq", &self.pq.to_vec())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for IdentityPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            classical: [u8; ED25519_PUBLIC_KEY_SIZE],
            pq: Vec<u8>,
        }
        let helper = Helper::deserialize(deserializer)?;
        let pq: [u8; ML_DSA_87_PUBLIC_KEY_SIZE] = helper
            .pq
            .as_slice()
            .try_into()
            .map_err(de::Error::custom)?;
        Ok(Self {
            classical: helper.classical,
            pq,
        })
    }
}

impl Serialize for MlDsa87PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MlDsa87PublicKey", 1)?;
        state.serialize_field("key", &self.key.to_vec())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MlDsa87PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            key: Vec<u8>,
        }
        let helper = Helper::deserialize(deserializer)?;
        let key: [u8; ML_DSA_87_PUBLIC_KEY_SIZE] = helper
            .key
            .as_slice()
            .try_into()
            .map_err(de::Error::custom)?;
        Ok(Self { key })
    }
}

impl Serialize for HybridSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HybridSignature", 2)?;
        state.serialize_field("classical", &self.classical.to_vec())?;
        state.serialize_field("pq", &self.pq)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for HybridSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            classical: Vec<u8>,
            pq: Vec<u8>,
        }
        let helper = Helper::deserialize(deserializer)?;
        let classical: [u8; ED25519_SIGNATURE_SIZE] = helper
            .classical
            .as_slice()
            .try_into()
            .map_err(de::Error::custom)?;
        Ok(Self {
            classical,
            pq: helper.pq,
        })
    }
}

impl Serialize for HybridKemPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HybridKemPublicKey", 2)?;
        state.serialize_field("classical", &self.classical)?;
        state.serialize_field("pq", &self.pq.to_vec())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for HybridKemPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            classical: [u8; X25519_PUBLIC_KEY_SIZE],
            pq: Vec<u8>,
        }
        let helper = Helper::deserialize(deserializer)?;
        let pq: [u8; ML_KEM_1024_PUBLIC_KEY_SIZE] = helper
            .pq
            .as_slice()
            .try_into()
            .map_err(de::Error::custom)?;
        Ok(Self {
            classical: helper.classical,
            pq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = IdentityKeyPair::generate().unwrap();
        let public = identity.public();
        assert_eq!(public.classical.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(public.pq.len(), ML_DSA_87_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_signature() {
        let identity = IdentityKeyPair::generate().unwrap();
        let message = b"test message";
        let sig = identity.sign_hybrid(message).unwrap();
        IdentityKeyPair::verify_hybrid(&identity.public(), message, &sig).unwrap();
    }

    #[test]
    fn test_hybrid_kem() {
        let (pub1, priv1) = HybridKemPublicKey::generate().unwrap();
        let (pub2, _priv2) = HybridKemPublicKey::generate().unwrap();

        let (ct, shared1) = priv1.encapsulate(&pub2).unwrap();
        let shared2 = _priv2.decapsulate(&ct, &pub1).unwrap();

        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_prekey_bundle() {
        let identity = IdentityKeyPair::generate().unwrap();
        let (spk_pub, _spk_priv) = HybridKemPublicKey::generate().unwrap();
        let spk = SignedPreKey {
            key_id: 1,
            public_key: spk_pub.clone(),
            signature: identity.sign_hybrid(&spk_pub.classical).unwrap(),
            timestamp: 1234567890,
        };

        let mut otpks = Vec::new();
        for i in 0..5 {
            let (otpk_pub, _) = HybridKemPublicKey::generate().unwrap();
            otpks.push(OneTimePreKey {
                key_id: i,
                public_key: otpk_pub,
            });
        }

        let bundle = PreKeyBundle::new(&identity, spk, otpks).unwrap();
        bundle.verify().unwrap();
    }

    #[test]
    fn test_hybrid_kem_serde() {
        let (public, _private) = HybridKemPublicKey::generate().unwrap();
        let encoded = serde_json::to_vec(&public).unwrap();
        let decoded: HybridKemPublicKey = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, public);
    }

    #[test]
    fn test_hybrid_signature_serde() {
        let identity = IdentityKeyPair::generate().unwrap();
        let sig = identity.sign_hybrid(b"serialized").unwrap();
        let encoded = serde_json::to_vec(&sig).unwrap();
        let decoded: HybridSignature = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, sig);
    }

    #[test]
    fn test_identity_from_seed_roundtrip() {
        let identity = IdentityKeyPair::generate().unwrap();
        let classical_seed = identity.classical_seed();
        let pq_seed = identity.pq_seed();

        let rebuilt = IdentityKeyPair::from_seed(&classical_seed, &pq_seed).unwrap();
        assert_eq!(rebuilt.public(), identity.public());

        let message = b"seeded identity";
        let signature = rebuilt.sign_hybrid(message).unwrap();
        IdentityKeyPair::verify_hybrid(&identity.public(), message, &signature).unwrap();
        assert_eq!(&identity.classical_seed()[..], &classical_seed[..]);
    }

    #[test]
    fn test_identity_from_seed_rejects_bad_sizes() {
        assert!(IdentityKeyPair::from_seed(&[1; 31], &[2; 32]).is_err());
        assert!(IdentityKeyPair::from_seed(&[1; 32], &[2; 31]).is_err());
    }
}
