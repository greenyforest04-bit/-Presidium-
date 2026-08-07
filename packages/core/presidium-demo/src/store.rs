//! Node-local encrypted storage for the demo: identity, prekey bundle,
//! session state and message history.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::Utc;
use presidium_crypto::identity::{
    HybridKemPrivateKey, HybridKemPublicKey, IdentityKeyPair, IdentityPublicKey,
    OneTimePreKey, PreKeyBundle, SignedPreKey, HybridSignature,
};
use presidium_storage::models::{
    ConversationRecord, IdentityRecord, MessageDirection, MessageRecord, MessageStatus,
};
use presidium_storage::{Database, SessionState, StorageError};
use serde::{Deserialize, Serialize};

/// Passphrase used to derive the database key (demo only).
const DEFAULT_PASSPHRASE: &[u8] = b"presidium-demo-passphrase";

/// Our signed prekey together with its private part, persisted as JSON.
#[derive(Clone, Serialize, Deserialize)]
pub struct PrekeyMaterial {
    /// Signed prekey id.
    pub key_id: u32,
    /// Public hybrid KEM key.
    pub public_key: HybridKemPublicKey,
    /// Classical (X25519) private part.
    pub private_classical: [u8; 32],
    /// PQ (ML-KEM-1024) private seed.
    pub private_pq: Vec<u8>,
    /// Signature over the public key by the identity key.
    pub signature: HybridSignature,
    /// Creation timestamp (Unix seconds).
    pub timestamp: u64,
}

impl PrekeyMaterial {
    /// Generate a fresh signed prekey for the identity.
    pub fn generate(identity: &IdentityKeyPair) -> Result<Self> {
        let (public_key, private) = HybridKemPublicKey::generate()?;
        let signature = identity.sign_hybrid(&public_key.classical)?;
        Ok(Self {
            key_id: 1,
            public_key,
            private_classical: private.classical,
            private_pq: private.pq.to_vec(),
            signature,
            timestamp: Utc::now().timestamp().max(0) as u64,
        })
    }

    /// Rebuild the private key part.
    pub fn private_key(&self) -> HybridKemPrivateKey {
        HybridKemPrivateKey {
            classical: self.private_classical,
            pq: self
                .private_pq
                .clone()
                .try_into()
                .expect("stored pq seed has the canonical size"),
        }
    }

    /// Rebuild the signed prekey struct.
    pub fn signed_prekey(&self) -> SignedPreKey {
        SignedPreKey {
            key_id: self.key_id,
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            timestamp: self.timestamp,
        }
    }

    /// Build the full bundle signed by the identity.
    pub fn to_bundle(&self, identity: &IdentityKeyPair) -> Result<PreKeyBundle> {
        Ok(PreKeyBundle::new(
            identity,
            self.signed_prekey(),
            Vec::<OneTimePreKey>::new(),
        )?)
    }
}

/// Encrypted database handle plus demo-specific conveniences.
pub struct NodeStore {
    db: Database,
    dir: PathBuf,
    /// Our hybrid identity, rebuilt from seeds on every boot.
    pub identity: IdentityKeyPair,
    /// Stable device id (hex string) bound to the network identity.
    pub device_id: String,
}

impl NodeStore {
    /// Open (creating if needed) the node database in `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key = db_key(dir)?;
        let db = Database::open(&dir.join("presidium.db"), key.as_slice())
            .map_err(|e| anyhow::anyhow!("open db: {e}"))?;
        let (identity, device_id) = load_or_create_identity(&db)?;
        Ok(Self {
            db,
            dir: dir.to_path_buf(),
            identity,
            device_id,
        })
    }

    /// Our crypto identity public key.
    pub fn identity_public(&self) -> IdentityPublicKey {
        self.identity.public()
    }

    /// Our persisted signed prekey, generating it on first boot.
    pub fn prekey(&self) -> Result<PrekeyMaterial> {
        let path = self.dir.join("bundle.json");
        if let Ok(text) = std::fs::read_to_string(&path) {
            return serde_json::from_str(&text).context("parse stored bundle");
        }
        let material = PrekeyMaterial::generate(&self.identity)?;
        std::fs::write(&path, serde_json::to_vec_pretty(&material)?)?;
        Ok(material)
    }

    /// Upsert the 1:1 conversation metadata.
    pub fn upsert_conversation(&self, id: &str, peer: &IdentityPublicKey, is_group: bool) -> Result<()> {
        self.db
            .upsert_conversation(&ConversationRecord {
                id: id.into(),
                peer_classical: peer.classical.to_vec(),
                peer_pq: peer.pq.to_vec(),
                is_group,
                created_at: Utc::now().timestamp_millis(),
            })
            .map_err(|e| anyhow::anyhow!("upsert conversation: {e}"))
    }

    /// Persist a conversation session state.
    pub fn save_session(&self, conversation_id: &str, state: &SessionState) -> Result<()> {
        self.db
            .save_session(conversation_id, state)
            .map_err(|e| anyhow::anyhow!("save session: {e}"))
    }

    /// Load a persisted conversation session, if any.
    pub fn load_session(&self, conversation_id: &str) -> Result<Option<SessionState>> {
        self.db
            .load_session(conversation_id)
            .map_err(|e| anyhow::anyhow!("load session: {e}"))
    }

    /// Store an incoming or outgoing message; returns the row id.
    pub fn insert_message(
        &self,
        conversation_id: &str,
        message_id: Vec<u8>,
        sender: &IdentityPublicKey,
        ciphertext: &[u8],
        header: &str,
        direction: MessageDirection,
    ) -> Result<i64> {
        let record = MessageRecord {
            id: 0,
            conversation_id: conversation_id.into(),
            message_id,
            sender_classical: sender.classical.to_vec(),
            ciphertext: ciphertext.to_vec(),
            header: header.into(),
            content_type: 0,
            direction,
            status: if direction == MessageDirection::Incoming {
                MessageStatus::Delivered
            } else {
                MessageStatus::Sent
            },
            created_at: Utc::now().timestamp_millis(),
        };
        self.db
            .insert_message(&record)
            .map_err(|e| anyhow::anyhow!("insert message: {e}"))
    }

    /// Mark a stored message as delivered or failed.
    pub fn update_message_status(&self, id: i64, status: MessageStatus) -> Result<()> {
        self.db
            .update_message_status(id, status)
            .map_err(|e| anyhow::anyhow!("update message status: {e}"))
    }

    /// Print the stored history of a conversation.
    pub fn print_history(&self, conversation_id: &str) -> Result<()> {
        let messages = self
            .db
            .list_messages(conversation_id, None, 100)
            .map_err(|e| anyhow::anyhow!("list messages: {e}"))?;
        if messages.is_empty() {
            println!("  (no messages in {conversation_id})");
            return Ok(());
        }
        for message in messages {
            let arrow = match message.direction {
                MessageDirection::Incoming => "<-",
                MessageDirection::Outgoing => "->",
            };
            let status = match message.status {
                MessageStatus::Pending => "pending",
                MessageStatus::Sent => "sent",
                MessageStatus::Delivered => "delivered",
                MessageStatus::Read => "read",
                MessageStatus::Failed => "failed",
            };
            println!(
                "  {arrow} [#{}] {status} {} bytes (header {})",
                message.id,
                message.ciphertext.len(),
                message.header
            );
        }
        Ok(())
    }
}

/// Derive the 32-byte sqleet key from the demo passphrase and a persisted salt.
fn db_key(dir: &Path) -> Result<[u8; 32]> {
    use presidium_crypto::constants::ARGON2_SALT_SIZE;

    let salt_path = dir.join("db.salt");
    let salt = if salt_path.exists() {
        let bytes = std::fs::read(&salt_path)?;
        let salt: [u8; ARGON2_SALT_SIZE] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored salt has wrong size"))?;
        salt
    } else {
        let salt = presidium_storage::kdf::generate_salt();
        std::fs::write(&salt_path, salt)?;
        salt
    };
    let key = presidium_storage::kdf::derive_db_key(DEFAULT_PASSPHRASE, &salt)
        .map_err(|e| anyhow::anyhow!("derive db key: {e}"))?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(key.as_ref());
    Ok(bytes)
}

/// Load the persisted identity, or generate and store a fresh one.
fn load_or_create_identity(db: &Database) -> Result<(IdentityKeyPair, String)> {
    match db.load_identity() {
        Ok(Some(record)) => {
            let identity = IdentityKeyPair::from_seed(&record.classical_seed, &record.pq_seed)?;
            Ok((identity, record.device_id))
        }
        Ok(None) => {
            let identity = IdentityKeyPair::generate()?;
            let (classical_seed, pq_seed) = identity.seeds();
            let device_id = random_hex_device_id();
            db.save_identity(&IdentityRecord {
                device_id: device_id.clone(),
                classical_seed: classical_seed.to_vec(),
                pq_seed: pq_seed.to_vec(),
                created_at: Utc::now().timestamp_millis(),
            })
            .map_err(|e: StorageError| anyhow::anyhow!("save identity: {e}"))?;
            Ok((identity, device_id))
        }
        Err(e) => bail!("load identity: {e}"),
    }
}

fn random_hex_device_id() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}
