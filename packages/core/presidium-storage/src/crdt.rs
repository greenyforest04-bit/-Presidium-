//! Yrs CRDT documents for multi-device conversation sync.

use yrs::updates::decoder::Decode;
use yrs::{Doc, GetString, ReadTxn, StateVector, Text, Transact, Update};

use crate::error::{Result, StorageError};

/// Content field name inside a conversation document.
pub const CONTENT_FIELD: &str = "content";

/// A single CRDT document (one per conversation / device).
///
/// Export produces a full-state update that any other replica can import;
/// updates merge deterministically regardless of order.
pub struct CrdtDocument {
    id: String,
    doc: Doc,
}

impl CrdtDocument {
    /// Create an empty document.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            doc: Doc::new(),
        }
    }

    /// Create a document from a previously exported update.
    pub fn from_bytes(id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let doc = Doc::new();
        let update = Update::decode_v1(bytes)
            .map_err(|e| StorageError::Crdt(format!("update decode: {e:?}")))?;
        doc.transact_mut()
            .apply_update(update)
            .map_err(|e| StorageError::Crdt(format!("update apply: {e:?}")))?;
        Ok(Self {
            id: id.into(),
            doc,
        })
    }

    /// Document id (conversation id or device id).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Append text to the document content.
    pub fn append_text(&mut self, text: &str) {
        let content = self.doc.get_or_insert_text(CONTENT_FIELD);
        let mut txn = self.doc.transact_mut();
        let len = content.len(&txn);
        content.insert(&mut txn, len, text);
    }

    /// Full text content of the document.
    pub fn text(&self) -> String {
        let content = self.doc.get_or_insert_text(CONTENT_FIELD);
        let txn = self.doc.transact();
        content.get_string(&txn)
    }

    /// Number of characters in the document.
    pub fn len(&self) -> usize {
        let content = self.doc.get_or_insert_text(CONTENT_FIELD);
        let txn = self.doc.transact();
        content.len(&txn) as usize
    }

    /// Whether the document contains no characters.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Export the full document state as an update blob.
    pub fn export(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.encode_state_as_update_v1(&StateVector::default())
    }

    /// Import (merge) an update produced by another replica.
    pub fn import(&mut self, bytes: &[u8]) -> Result<()> {
        let update = Update::decode_v1(bytes)
            .map_err(|e| StorageError::Crdt(format!("update decode: {e:?}")))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| StorageError::Crdt(format!("update apply: {e:?}")))
    }

    /// Import an export of another document wholesale.
    pub fn merge_from(&mut self, other: &CrdtDocument) -> Result<()> {
        self.import(&other.export())
    }
}

/// Two-way synchronize: exchange updates until both replicas converge.
pub fn sync(a: &mut CrdtDocument, b: &mut CrdtDocument) -> Result<()> {
    let update_a = a.export();
    let update_b = b.export();
    a.import(&update_b)?;
    b.import(&update_a)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_text() {
        let mut doc = CrdtDocument::new("conv-1");
        doc.append_text("hello");
        doc.append_text(", world");
        assert_eq!(doc.text(), "hello, world");
        assert_eq!(doc.len(), 12);
    }

    #[test]
    fn export_import_roundtrip() {
        let mut a = CrdtDocument::new("conv-1");
        a.append_text("persisted");
        let bytes = a.export();
        let b = CrdtDocument::from_bytes("conv-1", &bytes).unwrap();
        assert_eq!(b.text(), "persisted");
    }

    #[test]
    fn sync_converges_independent_edits() {
        let mut a = CrdtDocument::new("conv-1");
        let mut b = CrdtDocument::new("conv-1");
        a.append_text("alice|");
        b.append_text("bob");
        sync(&mut a, &mut b).unwrap();
        assert_eq!(a.text(), b.text());
        let text = a.text();
        assert!(text.contains("alice"));
        assert!(text.contains("bob"));
    }

    #[test]
    fn import_is_idempotent() {
        let mut a = CrdtDocument::new("conv-1");
        a.append_text("abc");
        let bytes = a.export();
        let mut b = CrdtDocument::new("conv-1");
        b.import(&bytes).unwrap();
        b.import(&bytes).unwrap();
        assert_eq!(b.text(), "abc");
    }
}