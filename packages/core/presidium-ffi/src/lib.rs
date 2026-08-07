//! Presidium FFI - UniFFI bindings layer
//! (Phase 1 Week 5 deliverable — bindings land in its week)

#![forbid(unsafe_code)]

pub use presidium_crypto;
pub use presidium_storage;
pub use presidium_network;
pub use presidium_sync;
pub use presidium_media;
pub use presidium_proto;

uniffi::setup_scaffolding!();