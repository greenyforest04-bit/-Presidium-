//! Peer discovery helpers: bootstrap parsing and address management.

use libp2p::multiaddr::Protocol;
use libp2p::PeerId;
use libp2p::Multiaddr;

use crate::error::{NetworkError, Result};

/// A parsed bootstrap peer: the peer id (if present) and its dialable address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// The peer id, when the address carried a `/p2p/<id>` suffix.
    pub peer: Option<PeerId>,
    /// The dialable multiaddr without the `/p2p/` suffix.
    pub address: Multiaddr,
}

/// Split a multiaddr into its dialable part and an optional trailing peer id.
pub fn parse_bootstrap_peer(addr: &Multiaddr) -> Result<BootstrapPeer> {
    let mut peer = None;
    let mut parts: Vec<_> = addr.iter().collect();
    if let Some(Protocol::P2p(id)) = parts.last() {
        peer = Some(*id);
        parts.pop();
    }
    if parts.is_empty() {
        return Err(NetworkError::InvalidAddress(format!(
            "no dialable address in {addr}"
        )));
    }
    let mut address = Multiaddr::empty();
    for part in parts {
        address.push(part);
    }
    Ok(BootstrapPeer { peer, address })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_address() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let parsed = parse_bootstrap_peer(&addr).unwrap();
        assert!(parsed.peer.is_none());
        assert_eq!(parsed.address, addr);
    }

    #[test]
    fn parses_address_with_peer_id() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWQJ6x2bYvG2RprK9xYJ9Q9JL7Nq5fQr7hLqCkfQjWz7sK"
            .parse()
            .unwrap();
        let parsed = parse_bootstrap_peer(&addr).unwrap();
        assert!(parsed.peer.is_some());
        assert_eq!(
            parsed.address.to_string(),
            "/ip4/127.0.0.1/tcp/4001"
        );
    }
}
