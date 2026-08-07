//! Chat session: PQXDH handshake over request-response, then Double Ratchet.

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use libp2p::PeerId;
use presidium_crypto::identity::{
    HybridKemPublicKey, IdentityKeyPair, IdentityPublicKey, PreKeyBundle,
};
use presidium_crypto::keys::SessionKeys;
use presidium_crypto::pqxdh::{
    pqxdh_initiator, pqxdh_responder, PqxdhInitiatorKeys, PqxdhOutput, PqxdhPrekeyMessage,
    PqxdhResponderKeys,
};
use presidium_crypto::ratchet::{DoubleRatchet, RatchetMessageHeader};
use presidium_network::P2pNode;
use presidium_proto::messages::NetworkEnvelope;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::store::{NodeStore, PrekeyMaterial};

/// Envelope kinds (mirrors `presidium.proto`).
pub const KIND_DIRECT: i32 = 1;
pub const KIND_GROUP: i32 = 2;
pub const KIND_SYNC: i32 = 3;

/// Handshake payload markers (first byte of the sync payload).
pub const MARKER_BUNDLE_REQ: u8 = 0;
pub const MARKER_BUNDLE: u8 = 1;
pub const MARKER_PREKEY: u8 = 2;
pub const MARKER_RATCHET_PUB: u8 = 3;
pub const MARKER_GROUP_KEY: u8 = 4;

/// Session id used when persisting the ratchet snapshot.
const SESSION_ID: &str = "presidium-session";

/// An established 1:1 chat session (Double Ratchet).
pub struct ChatSession {
    pub conversation_id: String,
    pub peer_identity: IdentityPublicKey,
    pub is_initiator: bool,
    pub ratchet: DoubleRatchet,
    session_keys: SessionKeys,
}

impl ChatSession {
    /// Encrypt a plaintext into a chat envelope (direct kind).
    pub fn encrypt(
        &mut self,
        identity: &IdentityKeyPair,
        device_id: &str,
        plaintext: &[u8],
    ) -> Result<NetworkEnvelope> {
        let (ciphertext, header) = self
            .ratchet
            .encrypt(plaintext)
            .context("ratchet encrypt")?;
        build_signed_envelope(
            identity,
            device_id,
            KIND_DIRECT,
            self.conversation_id.as_bytes(),
            &ciphertext,
            &header,
        )
    }

    /// Verify, ratchet and decrypt an inbound chat envelope.
    pub fn decrypt(&mut self, envelope: &NetworkEnvelope) -> Result<Vec<u8>> {
        let header = parse_header(&envelope.nonce)?;
        if !verify_envelope(&self.peer_identity, envelope)? {
            anyhow::bail!("signature verification failed");
        }
        let peer_ratchet = X25519PublicKey::from(header.dh_public_key);
        self.ratchet.dh_ratchet(peer_ratchet).context("dh ratchet")?;
        let plaintext = self
            .ratchet
            .decrypt(&envelope.encrypted_payload, &header)
            .context("ratchet decrypt")?;
        Ok(plaintext)
    }

    /// Persist the current ratchet snapshot.
    pub fn persist(&self, store: &NodeStore) -> Result<()> {
        let state = presidium_storage::SessionState {
            is_initiator: self.is_initiator,
            session_keys: self.session_keys.clone(),
            ratchet: Some(
                presidium_storage::session_state::RatchetSnapshot::from_ratchet(&self.ratchet),
            ),
            last_used: Utc::now().timestamp_millis(),
        };
        store.save_session(&self.conversation_id, &state)?;
        Ok(())
    }
}

/// Try to resume a persisted session for a conversation.
pub fn resume(store: &NodeStore, conversation_id: &str) -> Result<Option<ChatSession>> {
    let state = store.load_session(conversation_id)?;
    let Some(state) = state else {
        return Ok(None);
    };
    let ratchet = rebuild_ratchet(&state)?;
    Ok(Some(ChatSession {
        conversation_id: conversation_id.into(),
        peer_identity: state.session_keys.peer_identity.clone(),
        is_initiator: state.is_initiator,
        ratchet,
        session_keys: state.session_keys,
    }))
}

/// Rebuild a live ratchet from a persisted snapshot.
pub fn rebuild_ratchet(state: &presidium_storage::SessionState) -> Result<DoubleRatchet> {
    let snapshot = state
        .ratchet
        .as_ref()
        .context("no ratchet snapshot stored")?;
    snapshot
        .to_ratchet(SESSION_ID.into(), Vec::new())
        .context("rebuild ratchet from snapshot")
}

// ------------------------------------------------------------------ handshake

/// Initiator-side handshake driver.
pub struct InitiatorHandshake {
    identity: IdentityKeyPair,
    device_id: String,
    pub peer: PeerId,
    pub peer_identity: Option<IdentityPublicKey>,
    pending: Option<PqxdhOutput>,
}

impl InitiatorHandshake {
    pub fn new(identity: IdentityKeyPair, device_id: String, peer: PeerId) -> Self {
        Self {
            identity,
            device_id,
            peer,
            peer_identity: None,
            pending: None,
        }
    }

    /// Round 1: ask the responder for its prekey bundle.
    pub async fn request_bundle(&self, node: &P2pNode) -> Result<()> {
        node.send_direct(
            self.peer,
            sync_envelope(&self.identity, &self.device_id, MARKER_BUNDLE_REQ, &[])?,
        )
        .await
        .context("send bundle request")
    }

    /// Round 2: handle the responder's bundle, send our prekey message.
    pub async fn send_prekey(&mut self, node: &P2pNode, bundle: PreKeyBundle) -> Result<()> {
        bundle.verify().context("verify peer bundle")?;
        self.peer_identity = Some(bundle.identity_key.clone());

        let (_, ephemeral) = HybridKemPublicKey::generate()?;
        let (output, prekey_message) = pqxdh_initiator(PqxdhInitiatorKeys {
            identity: self.identity.clone(),
            ephemeral,
            peer_bundle: bundle,
        })
        .context("pqxdh initiator")?;
        self.pending = Some(output);

        let body = serde_json::to_vec(&prekey_message)?;
        node.send_direct(
            self.peer,
            sync_envelope(&self.identity, &self.device_id, MARKER_PREKEY, &body)?,
        )
        .await
        .context("send prekey message")
    }

    /// Round 3: responder's ratchet public key arrives; build the session.
    pub fn establish(&mut self, ratchet_public: &[u8]) -> Result<ChatSession> {
        let output = self.pending.take().context("no pqxdh output")?;
        let peer_identity = self
            .peer_identity
            .clone()
            .context("no peer identity")?;
        let peer_public: [u8; 32] = ratchet_public
            .try_into()
            .context("ratchet public must be 32 bytes")?;
        build_initiator_session(
            &self.identity,
            &self.device_id,
            output,
            peer_identity,
            X25519PublicKey::from(peer_public),
        )
    }
}

/// Responder-side handshake driver.
pub struct ResponderHandshake {
    identity: IdentityKeyPair,
    prekey: PrekeyMaterial,
    pub peer_identity: Option<IdentityPublicKey>,
}

impl ResponderHandshake {
    pub fn new(identity: IdentityKeyPair, prekey: PrekeyMaterial) -> Self {
        Self {
            identity,
            prekey,
            peer_identity: None,
        }
    }

    /// Our prekey bundle, signed by the identity.
    pub fn bundle(&self) -> Result<PreKeyBundle> {
        self.prekey.to_bundle(&self.identity)
    }

    /// Handle the initiator's prekey message.
    ///
    /// Returns the ratchet public key that must be sent back to complete the
    /// handshake, plus the established session (caller persists it).
    pub fn on_prekey(
        &mut self,
        body: &[u8],
        conversation_id: &str,
    ) -> Result<([u8; 32], ChatSession)> {
        let message: PqxdhPrekeyMessage =
            serde_json::from_slice(body).context("parse prekey message")?;
        self.peer_identity = Some(message.identity_public.clone());

        let output = pqxdh_responder(
            PqxdhResponderKeys {
                identity: self.identity.clone(),
                signed_prekey: self.prekey.private_key(),
                signed_prekey_id: self.prekey.key_id,
                one_time_prekey: None,
                one_time_prekey_id: None,
            },
            &message,
        )
        .context("pqxdh responder")?;

        let peer_identity = message.identity_public.clone();
        let keys = SessionKeys::new(false, &output.shared_secret, peer_identity.clone())
            .context("session keys")?;
        let our_ratchet = X25519StaticSecret::random();
        let ratchet = keys
            .to_ratchet(our_ratchet.clone(), None)
            .context("responder ratchet")?;
        let ratchet_public = X25519PublicKey::from(&our_ratchet).to_bytes();

        let session = ChatSession {
            conversation_id: conversation_id.into(),
            peer_identity,
            is_initiator: false,
            ratchet,
            session_keys: keys,
        };
        Ok((ratchet_public, session))
    }
}

// --------------------------------------------------------------------- helpers

/// Build the initiator's ratchet from the PQXDH output.
fn build_initiator_session(
    _identity: &IdentityKeyPair,
    device_id: &str,
    output: PqxdhOutput,
    peer_identity: IdentityPublicKey,
    peer_ratchet_public: X25519PublicKey,
) -> Result<ChatSession> {
    let keys = SessionKeys::new(true, &output.shared_secret, peer_identity.clone())
        .context("session keys")?;
    let our_ratchet = X25519StaticSecret::random();
    let ratchet = keys
        .to_ratchet(our_ratchet, Some(peer_ratchet_public))
        .context("initiator ratchet")?;

    Ok(ChatSession {
        conversation_id: device_id.to_string(),
        peer_identity,
        is_initiator: true,
        ratchet,
        session_keys: keys,
    })
}

/// Build a sync-kind envelope with a marker-prefixed payload.
pub fn sync_envelope(
    identity: &IdentityKeyPair,
    device_id: &str,
    marker: u8,
    body: &[u8],
) -> Result<NetworkEnvelope> {
    let mut payload = Vec::with_capacity(1 + body.len());
    payload.push(marker);
    payload.extend_from_slice(body);
    build_raw_envelope(identity, device_id, KIND_SYNC, device_id.as_bytes(), &payload, &[])
}

/// Build and sign a network envelope.
pub fn build_raw_envelope(
    identity: &IdentityKeyPair,
    device_id: &str,
    kind: i32,
    conversation_id: &[u8],
    payload: &[u8],
    header_json: &[u8],
) -> Result<NetworkEnvelope> {
    let signed = signed_bytes(header_json, payload);
    let signature = identity.sign_hybrid(&signed)?;
    let mac = sha256(payload);
    Ok(NetworkEnvelope {
        kind,
        conversation_id: Bytes::copy_from_slice(conversation_id),
        sender_device_id: Bytes::copy_from_slice(device_id.as_bytes()),
        timestamp: Utc::now().timestamp_millis().max(0) as u64,
        encrypted_payload: Bytes::copy_from_slice(payload),
        mac: Bytes::copy_from_slice(&mac),
        protocol_version: 1,
        nonce: Bytes::copy_from_slice(header_json),
        signature: Bytes::copy_from_slice(&serde_json::to_vec(&signature)?),
    })
}

/// Build a signed chat envelope: header JSON goes into the nonce slot.
pub fn build_signed_envelope(
    identity: &IdentityKeyPair,
    device_id: &str,
    kind: i32,
    conversation_id: &[u8],
    ciphertext: &[u8],
    header: &RatchetMessageHeader,
) -> Result<NetworkEnvelope> {
    let header_json = serde_json::to_vec(header)?;
    build_raw_envelope(identity, device_id, kind, conversation_id, ciphertext, &header_json)
}

/// Parse the ratchet header carried in the envelope nonce slot.
pub fn parse_header(nonce: &Bytes) -> Result<RatchetMessageHeader> {
    serde_json::from_slice(nonce).context("parse ratchet header")
}

/// Verify the envelope signature against a peer identity.
pub fn verify_envelope(peer: &IdentityPublicKey, envelope: &NetworkEnvelope) -> Result<bool> {
    let signature: presidium_crypto::identity::HybridSignature =
        serde_json::from_slice(&envelope.signature).context("parse signature")?;
    let signed = signed_bytes(&envelope.nonce, &envelope.encrypted_payload);
    Ok(IdentityKeyPair::verify_hybrid(peer, &signed, &signature).is_ok())
}

fn signed_bytes(header_json: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_json.len() + payload.len());
    out.extend_from_slice(header_json);
    out.extend_from_slice(payload);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
