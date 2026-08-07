//! PQXDH (Post-Quantum Extended Diffie-Hellman) Key Agreement
//!
//! Implements Signal Protocol v2 PQXDH specification with hybrid
//! classical + post-quantum cryptography.
//! Reference: https://signal.org/docs/specifications/pqxdh/

use crate::constants::*;
use crate::error::{CryptoError, Result};
use crate::identity::{
    HybridKemPrivateKey, HybridKemPublicKey, IdentityKeyPair, IdentityPublicKey, PreKeyBundle,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use rand::{rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PQXDH key agreement output - shared secret and metadata
#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub struct PqxdhOutput {
    /// Shared secret (32 bytes), derived via HKDF
    pub shared_secret: [u8; 32],
    /// Initiator's ephemeral public key (for responder to reconstruct)
    pub ephemeral_public: HybridKemPublicKey,
    /// Responder's signed prekey ID used
    pub signed_prekey_id: u32,
    /// Responder's one-time prekey ID used (if any)
    pub one_time_prekey_id: Option<u32>,
}

/// Keys needed for PQXDH as initiator
#[derive(Clone)]
pub struct PqxdhInitiatorKeys {
    /// Our identity key pair
    pub identity: IdentityKeyPair,
    /// Our ephemeral key pair (generated for this session)
    pub ephemeral: HybridKemPrivateKey,
    /// Responder's prekey bundle
    pub peer_bundle: PreKeyBundle,
}

/// Keys needed for PQXDH as responder
#[derive(Clone, Debug)]
pub struct PqxdhResponderKeys {
    /// Our identity key pair
    pub identity: IdentityKeyPair,
    /// Our signed prekey private key
    pub signed_prekey: HybridKemPrivateKey,
    /// Our signed prekey ID
    pub signed_prekey_id: u32,
    /// Our one-time prekey private key (optional)
    pub one_time_prekey: Option<HybridKemPrivateKey>,
    /// Our one-time prekey ID (if used)
    pub one_time_prekey_id: Option<u32>,
}

/// Initiator's pre-key message, sent as the first message of a PQXDH session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqxdhPrekeyMessage {
    /// Initiator's identity public key (IK_A)
    pub identity_public: IdentityPublicKey,
    /// Initiator's identity-derived hybrid KEM public key (X25519 + ML-KEM-1024)
    pub identity_kem_public: HybridKemPublicKey,
    /// Initiator's ephemeral hybrid KEM public key (EK_A)
    pub ephemeral_public: HybridKemPublicKey,
    /// Ciphertexts for DH1..DH4 in order: EK_A->SPK_B, IK_A->SPK_B, EK_A->IK_B, IK_A->IK_B
    pub ciphertexts: [Vec<u8>; 4],
    /// Ciphertext for DH5 (EK_A->OPK_B), present when a one-time prekey was used
    pub one_time_ciphertext: Option<Vec<u8>>,
    /// Responder's signed prekey ID used
    pub signed_prekey_id: u32,
    /// Responder's one-time prekey ID used (if any)
    pub one_time_prekey_id: Option<u32>,
}

/// Perform hybrid DH: combine classical X25519 and PQ ML-KEM shared secrets
fn hybrid_dh(
    our_key: &HybridKemPrivateKey,
    peer_public: &HybridKemPublicKey,
    ciphertext: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let ct = ciphertext.ok_or_else(|| {
        CryptoError::PqxdhError("Ciphertext required for decapsulation".into())
    })?;
    our_key.decapsulate(ct, peer_public)
}

/// Encapsulate (generate ciphertext + shared secret) for initiator
fn hybrid_encaps(
    our_key: &HybridKemPrivateKey,
    peer_public: &HybridKemPublicKey,
) -> Result<([u8; 32], Vec<u8>)> {
    let (ciphertext, shared) = our_key.encapsulate(peer_public)?;
    Ok((shared, ciphertext))
}

/// Derive the PQXDH master secret from the per-leg DH outputs.
///
/// Both parties concatenate the legs in the same order: DH1..DH4 always,
/// DH5 only when a one-time prekey was used.
fn derive_master_secret(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: &[u8; 32],
    dh5: Option<&[u8; 32]>,
) -> Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(4 * 32 + 32);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(dh4);
    if let Some(dh5) = dh5 {
        ikm.extend_from_slice(dh5);
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut shared_secret = [0u8; 32];
    hk.expand(b"PQXDH-MASTER", &mut shared_secret)
        .map_err(|_| CryptoError::KeyDerivationFailed("PQXDH master secret derivation failed".into()))?;
    Ok(shared_secret)
}

/// Derive root key and chain keys from PQXDH output
pub fn pqxdh_derive_keys(
    pqxdh_output: &PqxdhOutput,
) -> Result<([u8; ROOT_KEY_SIZE], [u8; CHAIN_KEY_SIZE])> {
    let hk = Hkdf::<Sha256>::new(None, &pqxdh_output.shared_secret);

    let mut root_key = [0u8; ROOT_KEY_SIZE];
    hk.expand(b"ROOT_KEY", &mut root_key)
        .map_err(|_| CryptoError::KeyDerivationFailed("Root key derivation failed".into()))?;

    let mut sending_chain = [0u8; CHAIN_KEY_SIZE];
    hk.expand(b"SENDING_CHAIN", &mut sending_chain)
        .map_err(|_| CryptoError::KeyDerivationFailed("Sending chain derivation failed".into()))?;

    Ok((root_key, sending_chain))
}

/// Perform PQXDH key agreement as initiator (Alice)
/// Reference: Signal Protocol v2 Section 3.2
pub fn pqxdh_initiator(keys: PqxdhInitiatorKeys) -> Result<(PqxdhOutput, PqxdhPrekeyMessage)> {
    let PqxdhInitiatorKeys {
        identity,
        ephemeral,
        peer_bundle,
    } = keys;

    // Verify peer bundle signature
    peer_bundle.verify()?;

    // Derive identity KEM keys
    let identity_kem = identity.kem_secret()?;

    // DH1: EK_A * SPK_B (Ephemeral - Signed PreKey)
    let (dh1, ct1) = hybrid_encaps(&ephemeral, &peer_bundle.signed_prekey.public_key)?;

    // DH2: IK_A * SPK_B (Identity - Signed PreKey)
    let (dh2, ct2) = hybrid_encaps(&identity_kem, &peer_bundle.signed_prekey.public_key)?;

    // DH3: EK_A * IK_B (Ephemeral - Identity)
    let (dh3, ct3) = hybrid_encaps(&ephemeral, &peer_bundle.identity_kem_public)?;

    // DH4: IK_A * IK_B (Identity - Identity)
    let (dh4, ct4) = hybrid_encaps(&identity_kem, &peer_bundle.identity_kem_public)?;

    // DH5: EK_A * OPK_B (Ephemeral - One-Time PreKey, optional)
    let (dh5, ct5, dh5_id) = if let Some(otpk) = peer_bundle.one_time_prekeys.first() {
        let (dh5_val, ct5_val) = hybrid_encaps(&ephemeral, &otpk.public_key)?;
        (dh5_val, Some(ct5_val), Some(otpk.key_id))
    } else {
        ([0u8; 32], None, None)
    };

    // Concatenate all DH outputs in canonical order and derive the master secret
    let shared_secret = derive_master_secret(&dh1, &dh2, &dh3, &dh4, dh5_id.map(|_| &dh5))?;

    let ephemeral_public = ephemeral.public_key();

    let message = PqxdhPrekeyMessage {
        identity_public: identity.public(),
        identity_kem_public: identity_kem.public_key(),
        ephemeral_public: ephemeral_public.clone(),
        ciphertexts: [ct1, ct2, ct3, ct4],
        one_time_ciphertext: ct5,
        signed_prekey_id: peer_bundle.signed_prekey.key_id,
        one_time_prekey_id: dh5_id,
    };

    Ok((
        PqxdhOutput {
            shared_secret,
            ephemeral_public,
            signed_prekey_id: message.signed_prekey_id,
            one_time_prekey_id: message.one_time_prekey_id,
        },
        message,
    ))
}

/// Perform PQXDH key agreement as responder (Bob)
/// Reference: Signal Protocol v2 Section 3.3
pub fn pqxdh_responder(
    keys: PqxdhResponderKeys,
    message: &PqxdhPrekeyMessage,
) -> Result<PqxdhOutput> {
    let identity = keys.identity.clone();
    let signed_prekey = keys.signed_prekey.clone();

    // Validate that we still hold the prekeys referenced by the message
    if message.signed_prekey_id != keys.signed_prekey_id {
        return Err(CryptoError::PqxdhError("Unknown signed prekey ID".into()));
    }
    let one_time_prekey = match (keys.one_time_prekey.clone(), message.one_time_prekey_id) {
        (Some(opk), Some(id)) if Some(id) == keys.one_time_prekey_id => Some(opk),
        (None, None) => None,
        _ => return Err(CryptoError::PqxdhError("Unknown one-time prekey ID".into())),
    };

    // Derive identity KEM keys
    let identity_kem = identity.kem_secret()?;

    // DH1: SPK_B * EK_A (Signed PreKey - Ephemeral)
    let dh1 = hybrid_dh(&signed_prekey, &message.ephemeral_public, Some(&message.ciphertexts[0]))?;

    // DH2: SPK_B * IK_A (Signed PreKey - Identity)
    let dh2 = hybrid_dh(&signed_prekey, &message.identity_kem_public, Some(&message.ciphertexts[1]))?;

    // DH3: IK_B * EK_A (Identity - Ephemeral)
    let dh3 = hybrid_dh(&identity_kem, &message.ephemeral_public, Some(&message.ciphertexts[2]))?;

    // DH4: IK_B * IK_A (Identity - Identity)
    let dh4 = hybrid_dh(&identity_kem, &message.identity_kem_public, Some(&message.ciphertexts[3]))?;

    // DH5: OPK_B * EK_A (One-Time PreKey - Ephemeral, optional)
    let dh5 = match (&one_time_prekey, &message.one_time_ciphertext) {
        (Some(opk), Some(ct)) => Some(hybrid_dh(opk, &message.ephemeral_public, Some(ct))?),
        _ => None,
    };

    // Concatenate all DH outputs in canonical order and derive the master secret
    let shared_secret = derive_master_secret(&dh1, &dh2, &dh3, &dh4, dh5.as_ref())?;

    Ok(PqxdhOutput {
        shared_secret,
        ephemeral_public: message.ephemeral_public.clone(),
        signed_prekey_id: message.signed_prekey_id,
        one_time_prekey_id: message.one_time_prekey_id,
    })
}

/// Encrypt a message with the shared secret (for initial pre-key message)
pub fn pqxdh_encrypt_initial(
    shared_secret: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(shared_secret.into());
    let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
    rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed("Initial message encryption failed".into()))?;

    // Prepend nonce
    let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt an initial message
pub fn pqxdh_decrypt_initial(
    shared_secret: &[u8; 32],
    message: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>> {
    if message.len() < CHACHA20_POLY1305_NONCE_SIZE {
        return Err(CryptoError::InvalidMessage("Message too short".into()));
    }

    let (nonce, ciphertext) = message.split_at(CHACHA20_POLY1305_NONCE_SIZE);
    let nonce_arr: [u8; CHACHA20_POLY1305_NONCE_SIZE] = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidMessage("Invalid nonce size".into()))?;
    let cipher = ChaCha20Poly1305::new(shared_secret.into());

    let plaintext = cipher
        .decrypt(
            (&nonce_arr).into(),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_dh_roundtrip() {
        let (pub1, priv1) = HybridKemPublicKey::generate().unwrap();
        let (pub2, _priv2) = HybridKemPublicKey::generate().unwrap();

        // Encapsulate
        let (shared1, ct1) = hybrid_encaps(&priv1, &pub2).unwrap();

        // Decapsulate using our own key pair and the peer's public key
        let shared2 = hybrid_dh(&_priv2, &pub1, Some(&ct1)).unwrap();

        // Both sides compute same secret
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_encrypt_decrypt_initial() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, world!";
        let aad = b"associated data";

        let ciphertext = pqxdh_encrypt_initial(&key, plaintext, aad).unwrap();
        let decrypted = pqxdh_decrypt_initial(&key, &ciphertext, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_pqxdh_full_handshake() {
        use crate::identity::{OneTimePreKey, SignedPreKey};
        use crate::keys::SessionKeys;
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

        // Identities
        let alice = IdentityKeyPair::generate().unwrap();
        let bob = IdentityKeyPair::generate().unwrap();

        // Bob's signed prekey and one-time prekey
        let (spk_pub, spk_priv) = HybridKemPublicKey::generate().unwrap();
        let spk = SignedPreKey {
            key_id: 1,
            public_key: spk_pub,
            signature: bob.sign_hybrid(b"presidium-signed-prekey").unwrap(),
            timestamp: 1234567890,
        };
        let (otpk_pub, otpk_priv) = HybridKemPublicKey::generate().unwrap();
        let otpk = OneTimePreKey {
            key_id: 7,
            public_key: otpk_pub,
        };

        let bundle = PreKeyBundle::new(&bob, spk, vec![otpk]).unwrap();
        bundle.verify().unwrap();

        // Alice's ephemeral key
        let (_epk_pub, epk_priv) = HybridKemPublicKey::generate().unwrap();

        // Handshake
        let (out_alice, prekey_message) = pqxdh_initiator(PqxdhInitiatorKeys {
            identity: alice.clone(),
            ephemeral: epk_priv,
            peer_bundle: bundle.clone(),
        })
        .unwrap();

        let out_bob = pqxdh_responder(
            PqxdhResponderKeys {
                identity: bob.clone(),
                signed_prekey: spk_priv,
                signed_prekey_id: 1,
                one_time_prekey: Some(otpk_priv),
                one_time_prekey_id: Some(7),
            },
            &prekey_message,
        )
        .unwrap();

        // Both sides derive the same master secret and agree on metadata
        assert_eq!(out_alice.shared_secret, out_bob.shared_secret);
        assert_eq!(out_alice.signed_prekey_id, out_bob.signed_prekey_id);
        assert_eq!(out_alice.one_time_prekey_id, out_bob.one_time_prekey_id);
        assert_eq!(out_alice.ephemeral_public, prekey_message.ephemeral_public);

        // Pre-key message round-trips through serialization
        let encoded = serde_json::to_vec(&prekey_message).unwrap();
        let decoded: PqxdhPrekeyMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.identity_public, prekey_message.identity_public);
        assert_eq!(decoded.identity_kem_public, prekey_message.identity_kem_public);

        // Session keys derive identically from the shared secret
        let session_alice = SessionKeys::new(true, &out_alice.shared_secret, bob.public()).unwrap();
        let session_bob = SessionKeys::new(false, &out_bob.shared_secret, alice.public()).unwrap();
        assert_eq!(session_alice.root_key, session_bob.root_key);
        assert_eq!(session_alice.sending_chain, session_bob.sending_chain);
        assert_eq!(session_alice.receiving_chain, session_bob.receiving_chain);

        // Fresh ratchet key pair per session
        let alice_ratchet = X25519StaticSecret::random();
        let alice_public = X25519PublicKey::from(&alice_ratchet);
        let bob_ratchet = X25519StaticSecret::random();
        let bob_public = X25519PublicKey::from(&bob_ratchet);

        let mut ratchet_alice = session_alice.to_ratchet(alice_ratchet, Some(bob_public)).unwrap();
        let mut ratchet_bob = session_bob.to_ratchet(bob_ratchet, None).unwrap();

        // Alice -> Bob
        let (ct, header) = ratchet_alice.encrypt(b"Hello, Bob!").unwrap();
        assert_eq!(header.dh_public_key, alice_public.to_bytes());
        ratchet_bob
            .dh_ratchet(X25519PublicKey::from(header.dh_public_key))
            .unwrap();
        let pt = ratchet_bob.decrypt(&ct, &header).unwrap();
        assert_eq!(&pt[..], b"Hello, Bob!");

        // Bob -> Alice reply
        let (ct2, header2) = ratchet_bob.encrypt(b"Hello, Alice!").unwrap();
        assert_eq!(header2.dh_public_key, bob_public.to_bytes());
        ratchet_alice
            .dh_ratchet(X25519PublicKey::from(header2.dh_public_key))
            .unwrap();
        let pt2 = ratchet_alice.decrypt(&ct2, &header2).unwrap();
        assert_eq!(&pt2[..], b"Hello, Alice!");
    }
}
