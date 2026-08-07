-- Presidium local storage schema (Phase 0 Week 3)
-- All values stored inside an SQLCipher-encrypted database.

-- Single-row identity: exactly one identity per install.
CREATE TABLE identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    device_id TEXT NOT NULL UNIQUE,
    classical_seed BLOB NOT NULL,
    pq_seed BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

-- Prekeys: signed prekeys and one-time prekeys.
CREATE TABLE prekeys (
    key_id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,              -- 0 = signed, 1 = one-time
    classical BLOB NOT NULL,
    pq BLOB NOT NULL,
    public_classical BLOB NOT NULL,
    public_pq BLOB NOT NULL,
    signature BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_prekeys_kind ON prekeys(kind, key_id);

-- Conversations (1:1 and group channels).
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    peer_classical BLOB NOT NULL,
    peer_pq BLOB NOT NULL,
    is_group INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Double Ratchet session state per conversation.
CREATE TABLE sessions (
    conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    is_initiator INTEGER NOT NULL,
    session_keys TEXT NOT NULL,         -- JSON: SessionKeys
    ratchet_state TEXT,                 -- JSON: RatchetSnapshot (nullable)
    last_used INTEGER NOT NULL
);

-- Messages with ratchet headers and ciphertext.
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    message_id BLOB NOT NULL,           -- sender-assigned unique id
    sender_classical BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    header TEXT NOT NULL,               -- JSON: RatchetMessageHeader
    content_type INTEGER NOT NULL,
    direction INTEGER NOT NULL,         -- 0 = incoming, 1 = outgoing
    status INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_messages_conversation ON messages(conversation_id, id);
CREATE UNIQUE INDEX idx_messages_uid ON messages(conversation_id, message_id);

-- Sender keys for group channels (SenderKey protocol).
CREATE TABLE sender_keys (
    group_id TEXT NOT NULL,
    sender_classical BLOB NOT NULL,
    chain_key BLOB NOT NULL,
    message_index INTEGER NOT NULL DEFAULT 0,
    key_id INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, sender_classical)
);

-- Media attachments.
CREATE TABLE media (
    id TEXT PRIMARY KEY,
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL,              -- 0 = image, 1 = audio, 2 = video, 3 = file
    encryption_key BLOB NOT NULL,
    size INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Yrs CRDT documents for multi-device sync (per conversation / device).
CREATE TABLE docs (
    id TEXT PRIMARY KEY,
    ydoc BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Known devices of linked identities.
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    classical BLOB NOT NULL,
    pq BLOB NOT NULL,
    last_seen INTEGER
);
