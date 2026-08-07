//! Presidium Storage - SQLCipher + Argon2id + Yrs CRDT encrypted local storage
//! (Phase 0 Week 3 deliverable)

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod crdt;
pub mod database;
pub mod error;
pub mod kdf;
pub mod models;
pub mod session_state;
pub mod store;

pub use database::Database;
pub use error::{Result, StorageError};
pub use models::{
    ConversationRecord, DeviceRecord, IdentityRecord, MediaRecord, MediaKind, MessageDirection,
    MessageRecord, MessageStatus, PreKeyKind, PreKeyRecord, SenderKeyRecord,
};
pub use session_state::SessionState;

pub use presidium_crypto;
