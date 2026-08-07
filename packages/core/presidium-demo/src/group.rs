//! Group chat: SenderKeys over GossipSub.

use anyhow::{Context, Result};
use libp2p::gossipsub::Sha256Topic;
use presidium_crypto::identity::{IdentityKeyPair, IdentityPublicKey};
use presidium_crypto::keys::{IdentityKey, SenderKeyMessage, SenderKeys};
use presidium_network::P2pNode;
use presidium_proto::messages::NetworkEnvelope;
use serde::{Deserialize, Serialize};

use crate::session;

/// Fixed demo group.
pub const DEMO_GROUP: &str = "presidium-demo-group";

/// Initial sender key distribution payload (sent over the 1:1 session).
#[derive(Clone, Serialize, Deserialize)]
pub struct GroupKeyDistribution {
    /// Sender key chain key (32 bytes).
    pub chain_key: [u8; 32],
    /// Sender key id.
    pub key_id: u64,
    /// Initial message index.
    pub message_index: u64,
}

/// A group chat bound to a gossipsub topic.
pub struct GroupChat {
    topic: Sha256Topic,
    group_id: Vec<u8>,
    pub conversation_id: String,
    pub sender: Option<SenderKeys>,
    pub receiver: Option<SenderKeys>,
    peer_identity: Option<IdentityPublicKey>,
}

impl GroupChat {
    /// Create the chat for the demo group.
    pub fn new() -> Result<Self> {
        let topic = presidium_network::topics::group_topic(DEMO_GROUP.as_bytes())?;
        Ok(Self {
            topic,
            group_id: DEMO_GROUP.as_bytes().to_vec(),
            conversation_id: format!("group:{DEMO_GROUP}"),
            sender: None,
            receiver: None,
            peer_identity: None,
        })
    }

    /// The gossipsub topic of the group.
    pub fn topic(&self) -> &Sha256Topic {
        &self.topic
    }

    /// Publisher side: create sender keys and produce the distribution
    /// payload to hand out over the secure 1:1 session.
    pub fn create_sender(&mut self, identity: &IdentityKeyPair) -> Result<GroupKeyDistribution> {
        let identity_key = IdentityKey {
            public: identity.public().classical.to_vec(),
        };
        let keys = SenderKeys::new(&self.group_id, &identity_key)?;
        let distribution = GroupKeyDistribution {
            chain_key: keys.chain_key,
            key_id: keys.key_id,
            message_index: keys.message_index,
        };
        self.sender = Some(keys);
        Ok(distribution)
    }

    /// Reader side: apply the distribution payload received over 1:1.
    pub fn apply_group_key(
        &mut self,
        distribution: GroupKeyDistribution,
        sender_identity: &IdentityPublicKey,
    ) {
        self.peer_identity = Some(sender_identity.clone());
        self.receiver = Some(SenderKeys {
            chain_key: distribution.chain_key,
            group_id: self.group_id.clone(),
            sender_identity: IdentityKey {
                public: sender_identity.classical.to_vec(),
            },
            message_index: distribution.message_index,
            key_id: distribution.key_id,
        });
    }

    /// Encrypt a plaintext and publish it to the group topic.
    pub async fn publish(
        &mut self,
        node: &P2pNode,
        identity: &IdentityKeyPair,
        device_id: &str,
        plaintext: &[u8],
    ) -> Result<()> {
        let sender = self.sender.as_mut().context("no sender keys")?;
        let ciphertext = sender.encrypt(plaintext, &self.group_id)?;
        let message_index = sender.message_index - 1;

        let message = SenderKeyMessage {
            group_id: self.group_id.clone(),
            sender_identity: IdentityKey {
                public: identity.public().classical.to_vec(),
            },
            message_index,
            ciphertext: ciphertext.clone(),
        };
        let envelope = session::build_raw_envelope(
            identity,
            device_id,
            session::KIND_GROUP,
            self.conversation_id.as_bytes(),
            &ciphertext,
            &serde_json::to_vec(&message)?,
        )?;
        node.publish(self.topic.clone(), envelope)
            .await
            .context("gossipsub publish")
    }

    /// Decrypt an inbound group message.
    pub fn decrypt(&mut self, envelope: &NetworkEnvelope) -> Result<Vec<u8>> {
        let peer = self
            .peer_identity
            .as_ref()
            .context("no group sender identity")?;
        if !session::verify_envelope(peer, envelope)? {
            anyhow::bail!("group signature verification failed");
        }
        let message: SenderKeyMessage =
            serde_json::from_slice(&envelope.nonce).context("parse group message")?;
        let receiver = self.receiver.as_mut().context("no receiver keys")?;
        let plaintext = receiver
            .decrypt(&envelope.encrypted_payload, message.message_index, &self.group_id)?;
        receiver.advance()?;
        Ok(plaintext)
    }
}

/// Short display form of a peer id.
pub fn short_peer(peer: libp2p::PeerId) -> String {
    let text = peer.to_string();
    if text.len() > 12 {
        format!("{}…{}", &text[..6], &text[text.len() - 4..])
    } else {
        text
    }
}
