//! Serialization and deserialization helpers for crypto types
//!
//! Uses serde_json by default with protocol-version tagged encoding.

use crate::error::{CryptoError, Result};
use serde::{de::DeserializeOwned, Serialize};

/// Magic bytes prefix for all Presidium serialized messages
pub const MAGIC: &[u8; 4] = b"PSDM";

/// Version tag for the serialization format
pub const FORMAT_VERSION: u8 = 1;

/// Trait for types that can be serialized/deserialized
pub trait Serializable: Serialize + DeserializeOwned {
    /// Serialize to bytes with magic + version header
    fn to_bytes(&self) -> Result<Vec<u8>>;
    /// Deserialize from bytes with magic + version header
    fn from_bytes(data: &[u8]) -> Result<Self>;
}

impl<T: Serialize + DeserializeOwned> Serializable for T {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serialize(self)
    }

    fn from_bytes(data: &[u8]) -> Result<Self> {
        deserialize(data)
    }
}

/// Serialize a type to a versioned byte buffer
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(value)?;
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Deserialize a type from a versioned byte buffer
pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T> {
    if data.len() < MAGIC.len() + 1 {
        return Err(CryptoError::InvalidMessage("Data too short".into()));
    }
    if &data[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidMessage("Invalid magic bytes".into()));
    }
    let version = data[MAGIC.len()];
    if version != FORMAT_VERSION {
        return Err(CryptoError::UnsupportedVersion(version as u32));
    }
    let payload = &data[MAGIC.len() + 1..];
    serde_json::from_slice(payload).map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestMessage {
        id: u64,
        data: Vec<u8>,
    }

    #[test]
    fn test_roundtrip() {
        let msg = TestMessage { id: 42, data: vec![1, 2, 3] };
        let bytes = serialize(&msg).unwrap();
        let back: TestMessage = deserialize(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn test_bad_version() {
        let msg = TestMessage { id: 1, data: vec![] };
        let mut bytes = serialize(&msg).unwrap();
        bytes[MAGIC.len()] = 99;
        let result: Result<TestMessage> = deserialize(&bytes);
        assert!(result.is_err());
    }
}