//! Presidium Network — libp2p P2P networking layer
//! (Phase 0 Week 4 deliverable)
//!
//! Provides a [`P2pNode`] that wraps a libp2p [`Swarm`] and exposes:
//! - TCP + Noise XX + Yamux transport,
//! - mDNS + Kademlia DHT discovery,
//! - GossipSub for groups / channels / stories,
//! - a protobuf request-response protocol for direct unicast messages.

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

pub mod behaviour;
pub mod codec;
pub mod config;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod node;
pub mod topics;

pub use behaviour::{PresidiumBehaviour, PresidiumEvent};
pub use codec::EnvelopeCodec;
pub use config::{KadMode, NodeConfig};
pub use error::{NetworkError, Result};
pub use identity::NetworkIdentity;
pub use node::{NodeEvent, P2pNode};

pub use presidium_crypto;
pub use presidium_proto;
