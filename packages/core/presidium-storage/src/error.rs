//! Error types for the Presidium storage layer.

use presidium_sqleet::SqlError;
use thiserror::Error;

/// Errors produced by the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Underlying sqleet/SQLite failure.
    #[error("database error: {0}")]
    Database(#[from] SqlError),

    /// Database key derivation (Argon2id) failure.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// JSON serialization/deserialization failure.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Yrs CRDT operation failure.
    #[error("crdt error: {0}")]
    Crdt(String),

    /// Stored data violates an invariant.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Schema migration failure.
    #[error("migration error: {0}")]
    Migration(String),
}

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, StorageError>;
