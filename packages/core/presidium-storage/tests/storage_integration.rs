//! Integration tests: full CRUD over an in-memory SQLCipher database.

use chrono::Utc;
use presidium_crypto::keys::SessionKeys;
use presidium_crypto::identity::IdentityKeyPair;
use presidium_storage::crdt::CrdtDocument;
use presidium_storage::kdf::derive_db_key;
use presidium_storage::models::{
    ConversationRecord, DeviceRecord, IdentityRecord, MediaKind, MediaRecord, MessageDirection,
    MessageRecord, MessageStatus, PreKeyKind, PreKeyRecord, SenderKeyRecord,
};
use presidium_storage::session_state::{RatchetSnapshot, SessionState};
use presidium_storage::Database;

fn test_db() -> Database {
    let key = derive_db_key(b"test-passphrase", b"0123456789abcdef").unwrap();
    Database::open_in_memory(key.as_slice()).unwrap()
}

fn now() -> i64 {
    Utc::now().timestamp_millis()
}

#[test]
fn identity_roundtrip() {
    let db = test_db();
    assert!(db.load_identity().unwrap().is_none());

    let record = IdentityRecord {
        device_id: "dev-001".into(),
        classical_seed: vec![1u8; 32],
        pq_seed: vec![2u8; 32],
        created_at: now(),
    };
    db.save_identity(&record).unwrap();
    assert_eq!(db.load_identity().unwrap().unwrap(), record);

    let updated = IdentityRecord {
        pq_seed: vec![3u8; 32],
        ..record
    };
    db.save_identity(&updated).unwrap();
    assert_eq!(db.load_identity().unwrap().unwrap(), updated);
}

#[test]
fn prekey_crud_and_atomic_take() {
    let db = test_db();
    for id in 0..3 {
        db.save_prekey(&PreKeyRecord {
            key_id: id,
            kind: PreKeyKind::OneTime,
            classical: vec![1; 32],
            pq: vec![2; 32],
            public_classical: vec![3; 32],
            public_pq: vec![4; 32],
            signature: Vec::new(),
            created_at: now(),
        })
        
        .unwrap();
    }
    db.save_prekey(&PreKeyRecord {
        key_id: 100,
        kind: PreKeyKind::Signed,
        classical: vec![1; 32],
        pq: vec![2; 32],
        public_classical: vec![3; 32],
        public_pq: vec![4; 32],
        signature: vec![5; 64],
        created_at: now(),
    })
    
    .unwrap();

    assert_eq!(db.count_prekeys(PreKeyKind::OneTime).unwrap(), 3);
    assert_eq!(db.count_prekeys(PreKeyKind::Signed).unwrap(), 1);

    let taken = db.take_one_time_prekey().unwrap().unwrap();
    assert_eq!(taken.key_id, 0);
    assert_eq!(db.count_prekeys(PreKeyKind::OneTime).unwrap(), 2);

    let taken_again = db.take_one_time_prekey().unwrap().unwrap();
    assert_eq!(taken_again.key_id, 1);

    db.delete_prekey(2).unwrap();
    assert_eq!(db.count_prekeys(PreKeyKind::OneTime).unwrap(), 0);

    let signed = db.list_prekeys(PreKeyKind::Signed, 10).unwrap();
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].signature.len(), 64);
}

#[test]
fn conversation_and_message_lifecycle() {
    let db = test_db();
    let conv = ConversationRecord {
        id: "conv-1".into(),
        peer_classical: vec![7; 32],
        peer_pq: vec![8; 32],
        is_group: false,
        created_at: now(),
    };
    db.upsert_conversation(&conv).unwrap();
    assert_eq!(db.load_conversation("conv-1").unwrap().unwrap(), conv);

    let msg = MessageRecord {
        id: 0,
        conversation_id: "conv-1".into(),
        message_id: vec![9; 16],
        sender_classical: vec![7; 32],
        ciphertext: vec![10; 64],
        header: "{\"dh_public_key\":\"aa\"}".into(),
        content_type: 0,
        direction: MessageDirection::Outgoing,
        status: MessageStatus::Pending,
        created_at: now(),
    };
    let id = db.insert_message(&msg).unwrap();
    assert!(id > 0);

    let loaded = db
        .load_message_by_uid("conv-1", &vec![9; 16])
        
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, id);
    assert_eq!(loaded.ciphertext, msg.ciphertext);

    db.update_message_status(id, MessageStatus::Delivered).unwrap();
    let updated = db.list_messages("conv-1", None, 10).unwrap();
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].status, MessageStatus::Delivered);

    let page = db.list_messages("conv-1", Some(id), 10).unwrap();
    assert!(page.is_empty(), "keyset pagination must exclude before_id");

    let dup = db
        .load_message_by_uid("conv-1", &vec![9; 16])
        
        .unwrap();
    assert!(dup.is_some());
}

#[test]
fn session_roundtrip_with_ratchet_snapshot() {
    let db = test_db();
    db.upsert_conversation(&ConversationRecord {
        id: "conv-2".into(),
        peer_classical: vec![1; 32],
        peer_pq: vec![2; 32],
        is_group: false,
        created_at: now(),
    })
    
    .unwrap();

let identity = IdentityKeyPair::generate().unwrap();
    let peer = identity.public();
    let keys = SessionKeys::new(true, &[6u8; 32], peer).unwrap();

    let mut ratchet = presidium_crypto::ratchet::DoubleRatchet::init(
        "conv-2".into(),
        presidium_crypto::ratchet::RootKey::new(keys.root_key),
        x25519_dalek::StaticSecret::from([11u8; 32]),
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([12u8; 32])),
        b"alice|bob".to_vec(),
    )
    .unwrap();
    ratchet.encrypt(b"advance the chain").unwrap();

    let state = SessionState {
        is_initiator: true,
        session_keys: keys,
        ratchet: Some(RatchetSnapshot::from_ratchet(&ratchet)),
        last_used: now(),
    };
    db.save_session("conv-2", &state).unwrap();

    let loaded = db.load_session("conv-2").unwrap().unwrap();
    assert_eq!(loaded.session_keys, state.session_keys);
    assert_eq!(loaded.ratchet, state.ratchet);

let rebuilt = loaded
        .ratchet
        .as_ref()
        .unwrap()
        .to_ratchet("conv-2".into(), b"alice|bob".to_vec())
        .unwrap();
    let mut rebuilt = rebuilt;
    let (ct, header) = rebuilt.encrypt(b"next").unwrap();
    assert!(!ct.is_empty());
    assert_eq!(header.message_number, 1, "chain index must survive the snapshot");

    db.delete_session("conv-2").unwrap();
    assert!(db.load_session("conv-2").unwrap().is_none());
}

#[test]
fn sender_key_upsert() {
    let db = test_db();
    let key = SenderKeyRecord {
        group_id: "group-1".into(),
        sender_classical: vec![1; 32],
        chain_key: vec![2; 32],
        message_index: 0,
        key_id: 7,
        updated_at: now(),
    };
    db.upsert_sender_key(&key).unwrap();
    assert_eq!(
        db.load_sender_key("group-1", &vec![1; 32])
            
            .unwrap()
            .unwrap(),
        key
    );

    let advanced = SenderKeyRecord {
        message_index: 3,
        chain_key: vec![9; 32],
        ..key
    };
    db.upsert_sender_key(&advanced).unwrap();
    let loaded = db
        .load_sender_key("group-1", &vec![1; 32])
        
        .unwrap()
        .unwrap();
    assert_eq!(loaded.message_index, 3);
}

#[test]
fn media_roundtrip() {
    let db = test_db();
    let media = MediaRecord {
        id: "media-1".into(),
        message_id: None,
        kind: MediaKind::Image,
        encryption_key: vec![1; 32],
        size: 4096,
        relative_path: "media/img-1.webp".into(),
        created_at: now(),
    };
    db.insert_media(&media).unwrap();
    assert_eq!(db.load_media("media-1").unwrap().unwrap(), media);

    let list = db.list_media_for_message(0).unwrap();
    assert!(list.is_empty(), "orphan media must not appear under a message id");
}

#[test]
fn device_list() {
    let db = test_db();
    db.upsert_device(&DeviceRecord {
        device_id: "phone".into(),
        classical: vec![1; 32],
        pq: vec![2; 32],
        last_seen: Some(now()),
    })
    
    .unwrap();
    db.upsert_device(&DeviceRecord {
        device_id: "laptop".into(),
        classical: vec![3; 32],
        pq: vec![4; 32],
        last_seen: None,
    })
    
    .unwrap();

    let devices = db.list_devices().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].device_id, "laptop");
}

#[test]
fn crdt_document_persistence() {
    let db = test_db();
let mut doc = CrdtDocument::new("conv-3");
    doc.append_text("hello from device A");
    let bytes = doc.export();

    db.save_doc("conv-3", &bytes).unwrap();
    let stored = db.load_doc("conv-3").unwrap().unwrap();
    assert!(!stored.is_empty());

let restored = CrdtDocument::from_bytes("conv-3", &stored).unwrap();
    assert_eq!(restored.text(), "hello from device A");

    db.delete_doc("conv-3").unwrap();
    assert!(db.load_doc("conv-3").unwrap().is_none());
}

