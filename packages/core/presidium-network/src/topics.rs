//! Gossipsub topic naming conventions.

use libp2p::gossipsub::Sha256Topic;

use crate::error::{NetworkError, Result};

/// Topic namespace prefix for all Presidium topics.
pub const TOPIC_PREFIX: &str = "/presidium";

/// Topic for a group conversation (multi-party chat).
pub fn group_topic(conversation_id: &[u8]) -> Result<Sha256Topic> {
    topic_for("group", conversation_id)
}

/// Topic for a channel broadcast (one-to-many).
pub fn channel_topic(conversation_id: &[u8]) -> Result<Sha256Topic> {
    topic_for("channel", conversation_id)
}

/// Topic for a device's stories feed.
pub fn stories_topic(device_id: &[u8]) -> Result<Sha256Topic> {
    topic_for("stories", device_id)
}

fn topic_for(kind: &str, id: &[u8]) -> Result<Sha256Topic> {
    if id.is_empty() {
        return Err(NetworkError::InvalidAddress(
            "topic id must not be empty".into(),
        ));
    }
    Ok(Sha256Topic::new(format!(
        "{TOPIC_PREFIX}/{kind}/{}",
        hex::encode(id)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_topic_format() {
        let topic = group_topic(&[1u8, 2, 3]).unwrap();
        assert_eq!(topic.to_string(), "/presidium/group/010203");
    }

    #[test]
    fn topic_types_are_distinct() {
        let group = group_topic(&[1u8]).unwrap();
        let channel = channel_topic(&[1u8]).unwrap();
        assert_ne!(group.to_string(), channel.to_string());
    }

    #[test]
    fn empty_id_is_rejected() {
        assert!(group_topic(&[]).is_err());
    }
}
