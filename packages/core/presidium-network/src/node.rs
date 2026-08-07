//! P2P node: swarm task, event channel, and control API.

use std::collections::HashMap;

use bytes::Bytes;
use futures::StreamExt;
use libp2p::gossipsub::{self, Sha256Topic, TopicHash};
use libp2p::mdns;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use presidium_proto::messages::{NetworkEnvelope, NetworkRequest, NetworkResponse};
use prost::Message;
use tokio::sync::{mpsc, oneshot};

use crate::behaviour::{PresidiumBehaviour, PresidiumEvent};
use crate::config::NodeConfig;
use crate::discovery;
use crate::error::{NetworkError, Result};
use crate::identity::NetworkIdentity;

/// Control messages sent from the public API to the swarm task.
enum Control {
    /// Dial an address (may carry a trailing `/p2p/<peer>`).
    Dial(Multiaddr),
    /// Send a direct message to a peer.
    SendDirect {
        peer: PeerId,
        envelope: NetworkEnvelope,
    },
    /// Publish an envelope to a gossipsub topic.
    Publish {
        topic: Sha256Topic,
        envelope: NetworkEnvelope,
    },
    /// Subscribe to a gossipsub topic.
    Subscribe(Sha256Topic),
    /// Unsubscribe from a gossipsub topic.
    Unsubscribe(Sha256Topic),
    /// Reply with the current listen addresses.
    ListenAddrs(oneshot::Sender<Vec<Multiaddr>>),
    /// Stop the node task.
    Shutdown,
}

/// Events reported by a [`P2pNode`] to the application.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// The node started listening on an address.
    Listen {
        /// The new listen address.
        address: Multiaddr,
    },
    /// A connection to a peer was established.
    PeerConnected {
        /// The connected peer.
        peer: PeerId,
    },
    /// A connection to a peer was closed.
    PeerDisconnected {
        /// The disconnected peer.
        peer: PeerId,
    },
    /// A peer was discovered (mDNS or DHT) together with a candidate address.
    PeerDiscovered {
        /// The discovered peer.
        peer: PeerId,
        /// A candidate address of the peer.
        address: Multiaddr,
    },
    /// An inbound direct message arrived.
    DirectMessage {
        /// The sending peer.
        from: PeerId,
        /// The message envelope.
        envelope: NetworkEnvelope,
    },
    /// An outbound direct message was acknowledged by the remote.
    DirectDelivered {
        /// The receiving peer.
        to: PeerId,
        /// Conversation id of the acknowledged envelope.
        conversation_id: Bytes,
        /// The response status.
        status: NetworkResponse,
    },
    /// An outbound direct message failed to be delivered.
    DirectFailed {
        /// The receiving peer.
        to: PeerId,
        /// Human-readable failure reason.
        error: String,
    },
    /// A gossipsub message arrived.
    GossipMessage {
        /// The peer that propagated the message.
        from: PeerId,
        /// The topic the message was published on.
        topic: TopicHash,
        /// The message envelope.
        envelope: NetworkEnvelope,
    },
}

/// A running P2P node.
///
/// Created via [`P2pNode::start`]. The underlying swarm runs in a tokio task;
/// application-facing events arrive on the returned channel.
pub struct P2pNode {
    identity: NetworkIdentity,
    control_tx: mpsc::Sender<Control>,
    task: tokio::task::JoinHandle<()>,
}

impl P2pNode {
    /// Build a swarm with the standard Presidium transport stack.
    fn build_swarm(
        identity: &NetworkIdentity,
        config: &NodeConfig,
    ) -> Result<Swarm<PresidiumBehaviour>> {
        let behaviour_config = config.clone();
        let swarm = SwarmBuilder::with_existing_identity(identity.keypair().clone())
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| NetworkError::Transport(e.to_string()))?
            .with_dns()
            .map_err(|e| NetworkError::Transport(e.to_string()))?
            .with_behaviour(move |key| {
                crate::behaviour::PresidiumBehaviour::new(key, &behaviour_config)
                    .map_err(|e| -> std::boxed::Box<dyn std::error::Error + Send + Sync> { e.into() })
            })
            .map_err(|e| NetworkError::Behaviour(e.to_string()))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_connection_timeout))
            .build();
        Ok(swarm)
    }

    /// Start a new node with the given configuration.
    ///
    /// Returns the node handle and a channel of [`NodeEvent`]s.
    pub async fn start(
        config: NodeConfig,
    ) -> Result<(Self, mpsc::Receiver<NodeEvent>)> {
        let identity = NetworkIdentity::generate();
        let swarm = Self::build_swarm(&identity, &config)?;

        let (control_tx, control_rx) = mpsc::channel(64);
        let (events_tx, events_rx) = mpsc::channel(256);

        let task = tokio::spawn(run_loop(swarm, control_rx, events_tx, config));

        Ok((
            Self {
                identity,
                control_tx,
                task,
            },
            events_rx,
        ))
    }

    /// Start a node with a deterministic identity derived from a device id.
    ///
    /// All devices that share a device id share the same libp2p identity, which
    /// is what multi-device sync expects. Prefer [`P2pNode::start`] in tests.
    pub async fn start_with_device_id(
        device_id: &[u8],
        config: NodeConfig,
    ) -> Result<(Self, mpsc::Receiver<NodeEvent>)> {
        let identity = NetworkIdentity::from_device_id(device_id);
        let swarm = Self::build_swarm(&identity, &config)?;

        let (control_tx, control_rx) = mpsc::channel(64);
        let (events_tx, events_rx) = mpsc::channel(256);

        let task = tokio::spawn(run_loop(swarm, control_rx, events_tx, config));

        Ok((
            Self {
                identity,
                control_tx,
                task,
            },
            events_rx,
        ))
    }

    /// The peer id of this node.
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// The current listen addresses.
    pub async fn listen_addrs(&self) -> Vec<Multiaddr> {
        let (tx, rx) = oneshot::channel();
        if self.control_tx.send(Control::ListenAddrs(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// Dial a peer by address (optionally with a `/p2p/<peer>` suffix).
    pub async fn dial(&self, addr: Multiaddr) -> Result<()> {
        self.control_tx
            .send(Control::Dial(addr))
            .await
            .map_err(|_| NetworkError::NotRunning)
    }

    /// Send a direct message to a peer over request-response.
    pub async fn send_direct(
        &self,
        peer: PeerId,
        envelope: NetworkEnvelope,
    ) -> Result<()> {
        self.control_tx
            .send(Control::SendDirect { peer, envelope })
            .await
            .map_err(|_| NetworkError::NotRunning)
    }

    /// Publish an envelope to a gossipsub topic.
    pub async fn publish(
        &self,
        topic: Sha256Topic,
        envelope: NetworkEnvelope,
    ) -> Result<()> {
        self.control_tx
            .send(Control::Publish { topic, envelope })
            .await
            .map_err(|_| NetworkError::NotRunning)
    }

    /// Subscribe to a gossipsub topic.
    pub async fn subscribe(&self, topic: Sha256Topic) -> Result<()> {
        self.control_tx
            .send(Control::Subscribe(topic))
            .await
            .map_err(|_| NetworkError::NotRunning)
    }

    /// Unsubscribe from a gossipsub topic.
    pub async fn unsubscribe(&self, topic: Sha256Topic) -> Result<()> {
        self.control_tx
            .send(Control::Unsubscribe(topic))
            .await
            .map_err(|_| NetworkError::NotRunning)
    }

    /// Stop the node, shutting down the swarm task.
    pub async fn stop(self) {
        let _ = self.control_tx.send(Control::Shutdown).await;
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn run_loop(
    mut swarm: Swarm<PresidiumBehaviour>,
    mut control: mpsc::Receiver<Control>,
    events: mpsc::Sender<NodeEvent>,
    config: NodeConfig,
) {
    // Pending outbound direct requests: request id -> (peer, conversation id).
    let mut pending: HashMap<OutboundRequestId, (PeerId, Bytes)> = HashMap::new();

    let listen_addrs = if config.listen.is_empty() {
        vec!["/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().expect("static addr")]
    } else {
        config.listen.clone()
    };
    for addr in listen_addrs {
        if let Err(e) = swarm.listen_on(addr) {
            tracing::warn!("listen failed: {e}");
        }
    }

    for topic_name in &config.subscribe_topics {
        subscribe(&mut swarm, &Sha256Topic::new(topic_name.clone()));
    }

    for addr in &config.bootstrap_peers {
        if let Ok(peer) = discovery::parse_bootstrap_peer(addr) {
            if let Some(peer_id) = peer.peer {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, peer.address.clone());
            }
            if let Err(e) = swarm.dial(peer.address.clone()) {
                tracing::debug!("bootstrap dial failed: {e}");
            }
        } else {
            tracing::warn!("skipping invalid bootstrap address {addr}");
        }
    }

    loop {
        tokio::select! {
            Some(ctrl) = control.recv() => {
                match ctrl {
                    Control::Dial(addr) => {
                        if let Err(e) = swarm.dial(addr) {
                            tracing::debug!("dial failed: {e}");
                        }
                    }
                    Control::SendDirect { peer, envelope } => {
                        let conversation_id = envelope.conversation_id.clone();
                        let request_id = swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, NetworkRequest { envelope: Some(envelope) });
                        pending.insert(request_id, (peer, conversation_id));
                    }
                    Control::Publish { topic, envelope } => {
                        let data = envelope.encode_to_vec();
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            tracing::debug!("publish failed: {e}");
                        }
                    }
                    Control::Subscribe(topic) => subscribe(&mut swarm, &topic),
                    Control::Unsubscribe(topic) => {
                        let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
                    }
                    Control::ListenAddrs(tx) => {
                        let _ = tx.send(swarm.listeners().cloned().collect());
                    }
                    Control::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &events, &mut pending, &config).await;
            }
        }
    }
}

fn subscribe(swarm: &mut Swarm<PresidiumBehaviour>, topic: &Sha256Topic) {
    match swarm.behaviour_mut().gossipsub.subscribe(topic) {
        Ok(_) => tracing::debug!("subscribed to {topic}"),
        Err(e) => tracing::warn!("subscription to {topic} failed: {e}"),
    }
}

async fn emit(events: &mpsc::Sender<NodeEvent>, event: NodeEvent) {
    if events.send(event).await.is_err() {
        tracing::debug!("event receiver closed");
    }
}

async fn handle_swarm_event(
    swarm: &mut Swarm<PresidiumBehaviour>,
    event: SwarmEvent<PresidiumEvent>,
    events: &mpsc::Sender<NodeEvent>,
    pending: &mut HashMap<OutboundRequestId, (PeerId, Bytes)>,
    config: &NodeConfig,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            emit(events, NodeEvent::Listen { address }).await;
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            emit(events, NodeEvent::PeerConnected { peer: peer_id }).await;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            emit(events, NodeEvent::PeerDisconnected { peer: peer_id }).await;
        }
        SwarmEvent::Behaviour(PresidiumEvent::Mdns(mdns::Event::Discovered(list))) => {
            if config.mdns_enabled {
                for (peer, address) in list {
                    swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer, address.clone());
                    emit(events, NodeEvent::PeerDiscovered { peer, address: address.clone() }).await;
                    if config.auto_dial {
                        if let Err(e) = swarm.dial(address) {
                            tracing::debug!("mdns dial failed: {e}");
                        }
                    }
                }
            }
        }
        SwarmEvent::Behaviour(PresidiumEvent::Mdns(mdns::Event::Expired(list))) => {
            if config.mdns_enabled {
                for (peer, address) in list {
                    swarm.behaviour_mut().kademlia.remove_address(&peer, &address);
                }
            }
        }
        SwarmEvent::Behaviour(PresidiumEvent::Kad(libp2p::kad::Event::RoutingUpdated {
            peer,
            addresses,
            ..
        })) => {
            let address = addresses.first().clone();
            emit(events, NodeEvent::PeerDiscovered { peer, address }).await;
        }
        SwarmEvent::Behaviour(PresidiumEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            match NetworkEnvelope::decode(message.data.as_ref()) {
                Ok(envelope) => {
                    emit(
                        events,
                        NodeEvent::GossipMessage {
                            from: propagation_source,
                            topic: message.topic,
                            envelope,
                        },
                    )
                    .await;
                }
                Err(e) => tracing::warn!("undecodable gossip message: {e}"),
            }
        }
        SwarmEvent::Behaviour(PresidiumEvent::RequestResponse(
            request_response::Event::Message { peer, message, .. },
        )) => match message {
            request_response::Message::Request { request, channel, .. } => {
                let ack_id = request
                    .envelope
                    .as_ref()
                    .map(|e| e.conversation_id.clone())
                    .unwrap_or_default();
                let status = NetworkResponse {
                    status: presidium_proto::messages::network_response::Status::Ok as i32,
                    ack_id,
                };
                if let Some(envelope) = request.envelope {
                    let _ = swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, status);
                    emit(events, NodeEvent::DirectMessage { from: peer, envelope }).await;
                }
            }
            request_response::Message::Response { response, request_id } => {
                if let Some((to, conversation_id)) = pending.remove(&request_id) {
                    emit(
                        events,
                        NodeEvent::DirectDelivered {
                            to,
                            conversation_id,
                            status: response,
                        },
                    )
                    .await;
                }
            }
        },
        SwarmEvent::Behaviour(PresidiumEvent::RequestResponse(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            },
        )) => {
            pending.remove(&request_id);
            emit(
                events,
                NodeEvent::DirectFailed {
                    to: peer,
                    error: error.to_string(),
                },
            )
            .await;
        }
        SwarmEvent::Behaviour(PresidiumEvent::RequestResponse(
            request_response::Event::InboundFailure { .. },
        )) => {}
        SwarmEvent::Behaviour(PresidiumEvent::Identify(_) | PresidiumEvent::Ping(_)) => {}
        SwarmEvent::Behaviour(_) => {}
        SwarmEvent::NewExternalAddrCandidate { .. }
        | SwarmEvent::IncomingConnection { .. }
        | SwarmEvent::Dialing { .. }
        | SwarmEvent::IncomingConnectionError { .. }
        | SwarmEvent::OutgoingConnectionError { .. }
        | SwarmEvent::ListenerClosed { .. }
        | SwarmEvent::ListenerError { .. }
        | SwarmEvent::ExpiredListenAddr { .. }
        | SwarmEvent::NewExternalAddrOfPeer { .. }
        | SwarmEvent::ExternalAddrExpired { .. } => {}
        _ => {}
    }
}
