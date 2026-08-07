//! Node configuration.

use std::time::Duration;

use libp2p::Multiaddr;

/// Kademlia DHT participation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KadMode {
    /// The node does not participate in the DHT.
    Disabled,
    /// The node queries the DHT but stores no records.
    #[default]
    Client,
    /// The node stores records and answers queries.
    Server,
}

/// Configuration for a [`P2pNode`](crate::P2pNode).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Addresses to listen on.
    ///
    /// Empty means an ephemeral address is chosen (`/ip4/0.0.0.0/tcp/0`).
    pub listen: Vec<Multiaddr>,
    /// Bootstrap peers to dial at startup.
    ///
    /// Addresses may carry a trailing `/p2p/<peer-id>` component.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable mDNS local network discovery.
    ///
    /// The mDNS behaviour is always constructed; when disabled, discovered
    /// peers are not dialed or reported. (Phase 0 keeps the behaviour
    /// always-on so the field can later gate construction properly.)
    pub mdns_enabled: bool,
    /// Whether to dial peers discovered via mDNS automatically.
    pub auto_dial: bool,
    /// Kademlia participation mode.
    pub kad_mode: KadMode,
    /// Gossipsub topics to subscribe to at startup.
    pub subscribe_topics: Vec<String>,
    /// Time without traffic after which an idle connection is closed.
    pub idle_connection_timeout: Duration,
    /// Timeout for direct (request-response) round trips.
    pub request_timeout: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            bootstrap_peers: Vec::new(),
            mdns_enabled: true,
            auto_dial: true,
            kad_mode: KadMode::Client,
            subscribe_topics: Vec::new(),
            idle_connection_timeout: Duration::from_secs(120),
            request_timeout: Duration::from_secs(30),
        }
    }
}
