//! Typed CRUD operations over the encrypted database.

use chrono::Utc;
use presidium_sqleet::{params, Row, SqlError};

use crate::database::Database;
use crate::error::{Result, StorageError};
use crate::models::{
    ConversationRecord, DeviceRecord, IdentityRecord, MediaRecord, MediaKind, MessageDirection,
    MessageRecord, MessageStatus, PreKeyKind, PreKeyRecord, SenderKeyRecord,
};
use crate::session_state::SessionState;

impl Database {
    // ---------------------------------------------------------------- identity

    /// Store (or replace) the single identity row.
    pub fn save_identity(&self, record: &IdentityRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO identity (id, device_id, classical_seed, pq_seed, created_at)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                     device_id = excluded.device_id,
                     classical_seed = excluded.classical_seed,
                     pq_seed = excluded.pq_seed",
                params![
                    &record.device_id,
                    &record.classical_seed,
                    &record.pq_seed,
                    record.created_at
                ],
            )?;
        Ok(())
    }

    /// Load the stored identity, if any.
    pub fn load_identity(&self) -> Result<Option<IdentityRecord>> {
        self.conn()
            .query_row(
                "SELECT device_id, classical_seed, pq_seed, created_at FROM identity WHERE id = 1",
                &[],
                |row| {
                    Ok(IdentityRecord {
                        device_id: row.get(0)?,
                        classical_seed: row.get(1)?,
                        pq_seed: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    // ----------------------------------------------------------------- prekeys

    /// Insert a signed or one-time prekey.
    pub fn save_prekey(&self, record: &PreKeyRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO prekeys
                 (key_id, kind, classical, pq, public_classical, public_pq, signature, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    record.key_id,
                    record.kind as i64,
                    &record.classical,
                    &record.pq,
                    &record.public_classical,
                    &record.public_pq,
                    &record.signature,
                    record.created_at,
                ],
            )?;
        Ok(())
    }

    /// List stored prekeys of a kind, oldest first.
    pub fn list_prekeys(&self, kind: PreKeyKind, limit: i64) -> Result<Vec<PreKeyRecord>> {
        let rows = self.conn().query_rows(
            "SELECT key_id, kind, classical, pq, public_classical, public_pq, signature, created_at
             FROM prekeys WHERE kind = ?1 ORDER BY key_id LIMIT ?2",
            params![kind as i64, limit],
            prekey_from_row,
        )?;
        Ok(rows)
    }

    /// Count stored prekeys of a kind.
    pub fn count_prekeys(&self, kind: PreKeyKind) -> Result<i64> {
        Ok(self
            .conn()
            .query_row(
                "SELECT count(*) FROM prekeys WHERE kind = ?1",
                params![kind as i64],
                |row| row.get(0),
            )?
            .unwrap_or(0))
    }

    /// Atomically take (consume) the oldest one-time prekey.
    pub fn take_one_time_prekey(&self) -> Result<Option<PreKeyRecord>> {
        let tx = self.conn().transaction()?;
        let record: Option<PreKeyRecord> = tx
            .query_row(
                "SELECT key_id, kind, classical, pq, public_classical, public_pq, signature, created_at
                 FROM prekeys WHERE kind = ?1 ORDER BY key_id LIMIT 1",
                params![PreKeyKind::OneTime as i64],
                prekey_from_row,
            )
            .map_err(StorageError::Database)?;
        if let Some(record) = &record {
            tx.execute("DELETE FROM prekeys WHERE key_id = ?1", params![record.key_id])?;
        }
        tx.commit()?;
        Ok(record)
    }

    /// Delete a prekey by id.
    pub fn delete_prekey(&self, key_id: i64) -> Result<()> {
        self.conn()
            .execute("DELETE FROM prekeys WHERE key_id = ?1", params![key_id])?;
        Ok(())
    }

    // ------------------------------------------------------------- conversations

    /// Upsert a conversation.
    pub fn upsert_conversation(&self, record: &ConversationRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO conversations (id, peer_classical, peer_pq, is_group, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                     peer_classical = excluded.peer_classical,
                     peer_pq = excluded.peer_pq,
                     is_group = excluded.is_group",
                params![
                    &record.id,
                    &record.peer_classical,
                    &record.peer_pq,
                    record.is_group,
                    record.created_at,
                ],
            )?;
        Ok(())
    }

    /// Load a conversation by id.
    pub fn load_conversation(&self, id: &str) -> Result<Option<ConversationRecord>> {
        self.conn()
            .query_row(
                "SELECT id, peer_classical, peer_pq, is_group, created_at FROM conversations WHERE id = ?1",
                params![id],
                |row| {
                    Ok(ConversationRecord {
                        id: row.get(0)?,
                        peer_classical: row.get(1)?,
                        peer_pq: row.get(2)?,
                        is_group: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    /// List all conversations, newest first.
    pub fn list_conversations(&self) -> Result<Vec<ConversationRecord>> {
        let rows = self.conn().query_rows(
            "SELECT id, peer_classical, peer_pq, is_group, created_at FROM conversations ORDER BY created_at DESC",
            &[],
            |row| {
                Ok(ConversationRecord {
                    id: row.get(0)?,
                    peer_classical: row.get(1)?,
                    peer_pq: row.get(2)?,
                    is_group: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- sessions

    /// Persist the session state of a conversation (upsert).
    pub fn save_session(&self, conversation_id: &str, state: &SessionState) -> Result<()> {
        let session_keys = serde_json::to_string(&state.session_keys)?;
        let ratchet_state = state
            .ratchet
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        self.conn()
            .execute(
                "INSERT INTO sessions (conversation_id, is_initiator, session_keys, ratchet_state, last_used)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(conversation_id) DO UPDATE SET
                     is_initiator = excluded.is_initiator,
                     session_keys = excluded.session_keys,
                     ratchet_state = excluded.ratchet_state,
                     last_used = excluded.last_used",
                params![
                    conversation_id,
                    state.is_initiator,
                    session_keys,
                    ratchet_state,
                    state.last_used,
                ],
            )?;
        Ok(())
    }

    /// Load the persisted session of a conversation.
    pub fn load_session(&self, conversation_id: &str) -> Result<Option<SessionState>> {
        let row = self.conn().query_row(
            "SELECT is_initiator, session_keys, ratchet_state, last_used FROM sessions WHERE conversation_id = ?1",
            params![conversation_id],
            |row| {
                Ok((
                    row.get::<bool>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Option<String>>(2)?,
                    row.get::<i64>(3)?,
                ))
            },
        )?;
        row.map(|(is_initiator, session_keys, ratchet_state, last_used)| {
            let session_keys = serde_json::from_str(&session_keys)?;
            let ratchet = ratchet_state
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?;
            Ok(SessionState {
                is_initiator,
                session_keys,
                ratchet,
                last_used,
            })
        })
        .transpose()
    }

    /// Delete a session (e.g. after a session reset).
    pub fn delete_session(&self, conversation_id: &str) -> Result<()> {
        self.conn()
            .execute(
                "DELETE FROM sessions WHERE conversation_id = ?1",
                params![conversation_id],
            )?;
        Ok(())
    }

    // ---------------------------------------------------------------- messages

    /// Insert a message, returning the row id.
    pub fn insert_message(&self, record: &MessageRecord) -> Result<i64> {
        self.conn()
            .execute(
                "INSERT INTO messages
                 (conversation_id, message_id, sender_classical, ciphertext, header,
                  content_type, direction, status, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    &record.conversation_id,
                    &record.message_id,
                    &record.sender_classical,
                    &record.ciphertext,
                    &record.header,
                    record.content_type,
                    record.direction as i64,
                    record.status as i64,
                    record.created_at,
                ],
            )?;
        Ok(self.conn().last_insert_rowid())
    }

    /// List messages of a conversation with keyset pagination (newest first).
    pub fn list_messages(
        &self,
        conversation_id: &str,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<MessageRecord>> {
        let rows = self.conn().query_rows(
            "SELECT id, conversation_id, message_id, sender_classical, ciphertext, header,
                    content_type, direction, status, created_at
             FROM messages
             WHERE conversation_id = ?1 AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC LIMIT ?3",
            params![conversation_id, before_id, limit],
            message_from_row,
        )?;
        Ok(rows)
    }

    /// Look up a message by its sender-assigned id.
    pub fn load_message_by_uid(
        &self,
        conversation_id: &str,
        message_id: &[u8],
    ) -> Result<Option<MessageRecord>> {
        self.conn()
            .query_row(
                "SELECT id, conversation_id, message_id, sender_classical, ciphertext, header,
                        content_type, direction, status, created_at
                 FROM messages WHERE conversation_id = ?1 AND message_id = ?2",
                params![conversation_id, message_id],
                message_from_row,
            )
            .map_err(Into::into)
    }

    /// Update the delivery status of a message.
    pub fn update_message_status(&self, id: i64, status: MessageStatus) -> Result<()> {
        self.conn()
            .execute(
                "UPDATE messages SET status = ?1 WHERE id = ?2",
                params![status as i64, id],
            )?;
        Ok(())
    }

    // -------------------------------------------------------------- sender keys

    /// Upsert a group sender key chain.
    pub fn upsert_sender_key(&self, record: &SenderKeyRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO sender_keys (group_id, sender_classical, chain_key, message_index, key_id, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(group_id, sender_classical) DO UPDATE SET
                     chain_key = excluded.chain_key,
                     message_index = excluded.message_index,
                     key_id = excluded.key_id,
                     updated_at = excluded.updated_at",
                params![
                    &record.group_id,
                    &record.sender_classical,
                    &record.chain_key,
                    record.message_index,
                    record.key_id,
                    record.updated_at,
                ],
            )?;
        Ok(())
    }

    /// Load the sender key chain for a group member.
    pub fn load_sender_key(
        &self,
        group_id: &str,
        sender_classical: &[u8],
    ) -> Result<Option<SenderKeyRecord>> {
        self.conn()
            .query_row(
                "SELECT group_id, sender_classical, chain_key, message_index, key_id, updated_at
                 FROM sender_keys WHERE group_id = ?1 AND sender_classical = ?2",
                params![group_id, sender_classical],
                |row| {
                    Ok(SenderKeyRecord {
                        group_id: row.get(0)?,
                        sender_classical: row.get(1)?,
                        chain_key: row.get(2)?,
                        message_index: row.get(3)?,
                        key_id: row.get(4)?,
                        updated_at: row.get(5)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    // ------------------------------------------------------------------- media

    /// Insert a media record.
    pub fn insert_media(&self, record: &MediaRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO media (id, message_id, kind, encryption_key, size, relative_path, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &record.id,
                    record.message_id,
                    record.kind as i64,
                    &record.encryption_key,
                    record.size,
                    &record.relative_path,
                    record.created_at,
                ],
            )?;
        Ok(())
    }

    /// Load a media record by id.
    pub fn load_media(&self, id: &str) -> Result<Option<MediaRecord>> {
        self.conn()
            .query_row(
                "SELECT id, message_id, kind, encryption_key, size, relative_path, created_at
                 FROM media WHERE id = ?1",
                params![id],
                |row| {
                    Ok(MediaRecord {
                        id: row.get(0)?,
                        message_id: row.get(1)?,
                        kind: media_kind_from_i64(row.get(2)?),
                        encryption_key: row.get(3)?,
                        size: row.get(4)?,
                        relative_path: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    /// List media attached to a message.
    pub fn list_media_for_message(&self, message_id: i64) -> Result<Vec<MediaRecord>> {
        let rows = self.conn().query_rows(
            "SELECT id, message_id, kind, encryption_key, size, relative_path, created_at
             FROM media WHERE message_id = ?1 ORDER BY created_at",
            params![message_id],
            |row| {
                Ok(MediaRecord {
                    id: row.get(0)?,
                    message_id: row.get(1)?,
                    kind: media_kind_from_i64(row.get(2)?),
                    encryption_key: row.get(3)?,
                    size: row.get(4)?,
                    relative_path: row.get(5)?,
                    created_at: row.get(6)?,
                })
            },
        )?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- CRDT docs

    /// Persist a CRDT document update blob.
    pub fn save_doc(&self, id: &str, ydoc_bytes: &[u8]) -> Result<()> {
        let updated_at = Utc::now().timestamp_millis();
        self.conn()
            .execute(
                "INSERT INTO docs (id, ydoc, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET ydoc = excluded.ydoc, updated_at = excluded.updated_at",
                params![id, ydoc_bytes, updated_at],
            )?;
        Ok(())
    }

    /// Load a persisted CRDT document blob.
    pub fn load_doc(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.conn()
            .query_row("SELECT ydoc FROM docs WHERE id = ?1", params![id], |row| row.get(0))
            .map_err(Into::into)
    }

    /// Delete a CRDT document.
    pub fn delete_doc(&self, id: &str) -> Result<()> {
        self.conn()
            .execute("DELETE FROM docs WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ----------------------------------------------------------------- devices

    /// Upsert a known device of a linked identity.
    pub fn upsert_device(&self, record: &DeviceRecord) -> Result<()> {
        self.conn()
            .execute(
                "INSERT INTO devices (device_id, classical, pq, last_seen)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(device_id) DO UPDATE SET
                     classical = excluded.classical,
                     pq = excluded.pq,
                     last_seen = excluded.last_seen",
                params![
                    &record.device_id,
                    &record.classical,
                    &record.pq,
                    record.last_seen
                ],
            )?;
        Ok(())
    }

    /// List all known devices.
    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        let rows = self.conn().query_rows(
            "SELECT device_id, classical, pq, last_seen FROM devices ORDER BY device_id",
            &[],
            |row| {
                Ok(DeviceRecord {
                    device_id: row.get(0)?,
                    classical: row.get(1)?,
                    pq: row.get(2)?,
                    last_seen: row.get(3)?,
                })
            },
        )?;
        Ok(rows)
    }
}

fn prekey_from_row(row: &Row) -> std::result::Result<PreKeyRecord, SqlError> {
    Ok(PreKeyRecord {
        key_id: row.get(0)?,
        kind: if row.get::<i64>(1)? == 0 {
            PreKeyKind::Signed
        } else {
            PreKeyKind::OneTime
        },
        classical: row.get(2)?,
        pq: row.get(3)?,
        public_classical: row.get(4)?,
        public_pq: row.get(5)?,
        signature: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn message_from_row(row: &Row) -> std::result::Result<MessageRecord, SqlError> {
    Ok(MessageRecord {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        message_id: row.get(2)?,
        sender_classical: row.get(3)?,
        ciphertext: row.get(4)?,
        header: row.get(5)?,
        content_type: row.get(6)?,
        direction: if row.get::<i64>(7)? == 0 {
            MessageDirection::Incoming
        } else {
            MessageDirection::Outgoing
        },
        status: match row.get::<i64>(8)? {
            0 => MessageStatus::Pending,
            1 => MessageStatus::Sent,
            2 => MessageStatus::Delivered,
            3 => MessageStatus::Read,
            _ => MessageStatus::Failed,
        },
        created_at: row.get(9)?,
    })
}

fn media_kind_from_i64(kind: i64) -> MediaKind {
    match kind {
        0 => MediaKind::Image,
        1 => MediaKind::Audio,
        2 => MediaKind::Video,
        _ => MediaKind::File,
    }
}
