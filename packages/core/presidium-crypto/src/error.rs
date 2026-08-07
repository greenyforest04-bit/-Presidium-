//! Error types for Presidium Crypto

use thiserror::Error;

/// Result type alias for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Comprehensive error types for cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key format or length
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Decryption failed (authentication tag mismatch)
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Invalid protocol version
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Ratchet state error
    #[error("Ratchet error: {0}")]
    RatchetError(String),

    /// PQXDH key agreement failed
    #[error("PQXDH failed: {0}")]
    PqxdhError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Operation not allowed in current state
    #[error("Illegal state: {0}")]
    IllegalState(String),

    /// Out of prekeys
    #[error("No one-time prekeys available")]
    NoPrekeysAvailable,

    /// Key rotation required
    #[error("Key rotation required")]
    KeyRotationRequired,

    /// Memory protection error
    #[error("Secure memory error: {0}")]
    MemoryError(String),
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::SerializationError(e.to_string())
    }
}

impl From<prost::EncodeError> for CryptoError {
    fn from(e: prost::EncodeError) -> Self {
        CryptoError::SerializationError(e.to_string())
    }
}

impl From<prost::DecodeError> for CryptoError {
    fn from(e: prost::DecodeError) -> Self {
        CryptoError::SerializationError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = CryptoError::InvalidKey("too short".to_string());
        assert_eq!(err.to_string(), "Invalid key: too short");
    }

    #[test]
    fn error_debug() {
        let err = CryptoError::DecryptionFailed;
        let debug = format!("{:?}", err);
        assert!(debug.contains("DecryptionFailed"));
    }
}