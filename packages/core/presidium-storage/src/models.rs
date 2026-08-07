//! Typed records for the local database.

use serde::{Deserialize, Serialize};

/// Single-row identity of the local installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecord {
    /// Stable device identifier.
    pub device_id: String,
    /// Ed25519 seed (32 bytes).
    pub classical_seed: Vec<u8>,
    /// ML-DSA-87 seed (32 bytes).
    pub pq_seed: Vec<u8>,
    /// Unix timestamp (ms).
    pub created_at: i64,
}

/// Prekey kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum PreKeyKind {
    /// Signed prekey, rotated infrequently.
    Signed = 0,
    /// One-time prekey, consumed by a single handshake.
    OneTime = 1,
}

/// A stored (signed or one-time) prekey with its public parts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyRecord {
    pub key_id: i64,
    pub kind: PreKeyKind,
    /// Classical (X25519) secret, 32 bytes.
    pub classical: Vec<u8>,
    /// PQC (ML-KEM-1024) secret.
    pub pq: Vec<u8>,
    pub public_classical: Vec<u8>,
    pub public_pq: Vec<u8>,
    /// Signature over the signed prekey (empty for one-time keys).
    pub signature: Vec<u8>,
    /// Unix timestamp (ms).
    pub created_at: i64,
}

/// A conversation (1:1 or group channel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationRecord {
    /// Stable conversation id (uuid string for 1:1, group id otherwise).
    pub id: String,
    /// Peer classical identity public key.
    pub peer_classical: Vec<u8>,
    /// Peer PQC identity public key.
    pub peer_pq: Vec<u8>,
    pub is_group: bool,
    /// Unix timestamp (ms).
    pub created_at: i64,
}

/// Message direction from the local perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageDirection {
    /// Received from a peer.
    Incoming = 0,
    /// Sent by this device.
    Outgoing = 1,
}

/// Delivery status of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MessageStatus {
    Pending = 0,
    Sent = 1,
    Delivered = 2,
    Read = 3,
    Failed = 4,
}

/// A stored message: ratchet ciphertext plus envelope metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecord {
    pub id: i64,
    pub conversation_id: String,
    /// Sender-assigned unique message id.
    pub message_id: Vec<u8>,
    /// Sender classical identity public key.
    pub sender_classical: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// JSON-serialized ratchet header.
    pub header: String,
    pub content_type: i64,
    pub direction: MessageDirection,
    pub status: MessageStatus,
    /// Unix timestamp (ms).
    pub created_at: i64,
}

/// SenderKey chain state for a group member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyRecord {
    pub group_id: String,
    /// Sender classical identity public key.
    pub sender_classical: Vec<u8>,
    pub chain_key: Vec<u8>,
    pub message_index: i64,
    pub key_id: i64,
    /// Unix timestamp (ms).
    pub updated_at: i64,
}

/// Media attachment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i64)]
pub enum MediaKind {
    Image = 0,
    Audio = 1,
    Video = 2,
    File = 3,
}

/// Stored media attachment metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaRecord {
    pub id: String,
    pub message_id: Option<i64>,
    pub kind: MediaKind,
    /// Per-file encryption key (32 bytes).
    pub encryption_key: Vec<u8>,
    pub size: i64,
    /// Path relative to the media directory.
    pub relative_path: String,
    /// Unix timestamp (ms).
    pub created_at: i64,
}

/// A known device of a linked identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub classical: Vec<u8>,
    pub pq: Vec<u8>,
    /// Unix timestamp (ms), `None` if never seen.
    pub last_seen: Option<i64>,
}
