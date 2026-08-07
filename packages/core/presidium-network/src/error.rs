//! Error types for the networking layer.

use thiserror::Error;

/// Result alias for the networking layer.
pub type Result<T> = std::result::Result<T, NetworkError>;

/// Errors produced by the network layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The swarm failed to listen on a requested address.
    #[error("listen failure: {0}")]
    Listen(String),
    /// Dialing a peer failed.
    #[error("dial failure: {0}")]
    Dial(String),
    /// Publishing a message to a gossipsub topic failed.
    #[error("publish failure: {0}")]
    Publish(String),
    /// A network behaviour could not be constructed.
    #[error("behaviour construction: {0}")]
    Behaviour(String),
    /// Transport construction failed.
    #[error("transport construction: {0}")]
    Transport(String),
    /// The supplied key material is invalid.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// A multiaddr is malformed or unsupported.
    #[error("invalid multiaddr: {0}")]
    InvalidAddress(String),
    /// The node task has terminated.
    #[error("node is not running")]
    NotRunning,
}
