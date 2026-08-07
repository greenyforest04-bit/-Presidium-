//! Composed network behaviour for a Presidium node.

use libp2p::identity::Keypair;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::mdns;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, ping};
use presidium_proto::messages::{NetworkRequest, NetworkResponse};

use crate::codec::{EnvelopeCodec, REQUEST_RESPONSE_PROTOCOL};
use crate::config::{KadMode, NodeConfig};
use crate::error::{NetworkError, Result};

/// The combined behaviour of a Presidium node.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "PresidiumEvent")]
pub struct PresidiumBehaviour {
    /// Peer identity protocol (address exchange).
    pub identify: identify::Behaviour,
    /// Keepalive / liveness probes.
    pub ping: ping::Behaviour,
    /// Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Local network discovery via mDNS.
    pub mdns: mdns::tokio::Behaviour,
    /// Group / channel / stories pubsub.
    pub gossipsub: gossipsub::Behaviour,
    /// Direct unicast messages (protobuf request-response).
    pub request_response: request_response::Behaviour<EnvelopeCodec>,
}

/// Events produced by the composed behaviour.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum PresidiumEvent {
    /// Identify protocol event.
    Identify(identify::Event),
    /// Ping event.
    Ping(ping::Event),
    /// Kademlia event.
    Kad(kad::Event),
    /// mDNS event.
    Mdns(mdns::Event),
    /// Gossipsub event.
    Gossipsub(gossipsub::Event),
    /// Request-response event.
    RequestResponse(request_response::Event<NetworkRequest, NetworkResponse>),
}

impl From<identify::Event> for PresidiumEvent {
    fn from(event: identify::Event) -> Self {
        PresidiumEvent::Identify(event)
    }
}

impl From<ping::Event> for PresidiumEvent {
    fn from(event: ping::Event) -> Self {
        PresidiumEvent::Ping(event)
    }
}

impl From<kad::Event> for PresidiumEvent {
    fn from(event: kad::Event) -> Self {
        PresidiumEvent::Kad(event)
    }
}

impl From<mdns::Event> for PresidiumEvent {
    fn from(event: mdns::Event) -> Self {
        PresidiumEvent::Mdns(event)
    }
}

impl From<gossipsub::Event> for PresidiumEvent {
    fn from(event: gossipsub::Event) -> Self {
        PresidiumEvent::Gossipsub(event)
    }
}

impl From<request_response::Event<NetworkRequest, NetworkResponse>> for PresidiumEvent {
    fn from(event: request_response::Event<NetworkRequest, NetworkResponse>) -> Self {
        PresidiumEvent::RequestResponse(event)
    }
}

/// Protocol id advertised to identify peers.
const IDENTIFY_PROTOCOL_VERSION: &str = concat!("/presidium/identify/", env!("CARGO_PKG_VERSION"));
/// Protocol id for the Kademlia DHT.
const KAD_PROTOCOL_NAME: &str = "/presidium/kad/0.1.0";

impl PresidiumBehaviour {
    /// Build the composed behaviour for the given identity and configuration.
    pub fn new(keypair: &Keypair, config: &NodeConfig) -> Result<Self> {
        let local_peer_id = keypair.public().to_peer_id();

        let identify = identify::Behaviour::new(identify::Config::new(
            IDENTIFY_PROTOCOL_VERSION.to_string(),
            keypair.public(),
        ));

        let ping = ping::Behaviour::new(ping::Config::new());

        let kademlia = match config.kad_mode {
            KadMode::Disabled => {
                let mut behaviour = kad::Behaviour::new(local_peer_id, MemoryStore::new(local_peer_id));
                behaviour.set_mode(Some(kad::Mode::Client));
                behaviour
            }
            KadMode::Client => kad::Behaviour::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                kad::Config::new(libp2p::StreamProtocol::new(KAD_PROTOCOL_NAME)),
            ),
            KadMode::Server => {
                let mut behaviour = kad::Behaviour::with_config(
                    local_peer_id,
                    MemoryStore::new(local_peer_id),
                    kad::Config::new(libp2p::StreamProtocol::new(KAD_PROTOCOL_NAME)),
                );
                behaviour.set_mode(Some(kad::Mode::Server));
                behaviour
            }
        };

        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
            .map_err(|e| NetworkError::Behaviour(format!("mdns: {e}")))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub::Config::default(),
        )
        .map_err(|e| NetworkError::Behaviour(format!("gossipsub: {e}")))?;

        let request_response = request_response::Behaviour::with_codec(
            EnvelopeCodec,
            vec![(
                REQUEST_RESPONSE_PROTOCOL.to_string(),
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout),
        );

        Ok(Self {
            identify,
            ping,
            kademlia,
            mdns,
            gossipsub,
            request_response,
        })
    }
}
