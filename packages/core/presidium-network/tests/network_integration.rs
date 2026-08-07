//! Integration tests: two real `P2pNode`s talking over TCP + Noise + Yamux.

use std::time::Duration;

use bytes::Bytes;
use multiaddr::Protocol;
use presidium_network::{KadMode, NodeConfig, NodeEvent, P2pNode};
use presidium_proto::messages::network_response::Status;
use presidium_proto::messages::NetworkEnvelope;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// Short-lived test configuration: ephemeral TCP listener, no DHT, no mDNS.
fn test_config() -> NodeConfig {
    NodeConfig {
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        mdns_enabled: false,
        auto_dial: false,
        kad_mode: KadMode::Disabled,
        request_timeout: Duration::from_secs(10),
        idle_connection_timeout: Duration::from_secs(120),
        ..NodeConfig::default()
    }
}

fn envelope(conversation_id: &[u8]) -> NetworkEnvelope {
    NetworkEnvelope {
        kind: 1,
        conversation_id: Bytes::from(conversation_id.to_vec()),
        sender_device_id: Bytes::from(vec![1, 2, 3]),
        timestamp: 42,
        encrypted_payload: Bytes::from(vec![9, 9, 9]),
        mac: Bytes::from(vec![1]),
        protocol_version: 1,
        nonce: Bytes::from(vec![2]),
        signature: Bytes::from(vec![3]),
    }
}

async fn wait_for(
    rx: &mut mpsc::Receiver<NodeEvent>,
    pred: impl Fn(&NodeEvent) -> bool,
    limit: Duration,
) -> NodeEvent {
    let deadline = std::time::Instant::now() + limit;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for event");
        }
        let event = timeout(remaining, rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("event channel closed");
        if pred(&event) {
            return event;
        }
    }
}

fn tcp_addr(addrs: Vec<libp2p::Multiaddr>) -> libp2p::Multiaddr {
    addrs
        .into_iter()
        .find(|a| a.iter().any(|p| matches!(p, Protocol::Tcp(_))))
        .expect("no tcp listen address")
}

/// Wait until the node's TCP socket is actually bound.
async fn wait_listening(rx: &mut mpsc::Receiver<NodeEvent>, node: &P2pNode) {
    let _ = wait_for(rx, |e| matches!(e, NodeEvent::Listen { .. }), Duration::from_secs(10)).await;
    assert!(!node.listen_addrs().await.is_empty());
}

#[tokio::test]
async fn direct_message_roundtrip() {
    let (node_a, mut events_a) = P2pNode::start(test_config()).await.unwrap();
    let (node_b, mut events_b) = P2pNode::start(test_config()).await.unwrap();

    wait_listening(&mut events_b, &node_b).await;

    let addr_b = tcp_addr(node_b.listen_addrs().await)
        .with(Protocol::P2p(node_b.peer_id()));
    node_a.dial(addr_b).await.unwrap();

    wait_for(&mut events_a, |e| {
        matches!(e, NodeEvent::PeerConnected { peer } if *peer == node_b.peer_id())
    }, Duration::from_secs(10)).await;

    let envelope = envelope(b"conv-direct");
    node_a.send_direct(node_b.peer_id(), envelope.clone()).await.unwrap();

    let received = wait_for(&mut events_b, |e| {
        matches!(e, NodeEvent::DirectMessage { envelope: env, .. } if env == &envelope)
    }, Duration::from_secs(10)).await;
    match received {
        NodeEvent::DirectMessage { from, .. } => assert_eq!(from, node_a.peer_id()),
        other => panic!("unexpected event: {other:?}"),
    }

    let delivered = wait_for(&mut events_a, |e| {
        matches!(e, NodeEvent::DirectDelivered { to, .. } if *to == node_b.peer_id())
    }, Duration::from_secs(10)).await;
    match delivered {
        NodeEvent::DirectDelivered { conversation_id, status, .. } => {
            assert_eq!(conversation_id, Bytes::from(b"conv-direct".to_vec()));
            assert_eq!(
                status.status,
                Status::Ok as i32,
                "expected STATUS_OK, got {status:?}"
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    node_a.stop().await;
    node_b.stop().await;
}

#[tokio::test]
async fn direct_message_to_unknown_peer_fails() {
    let (node_a, mut events_a) = P2pNode::start(test_config()).await.unwrap();
    let (node_b, _events_b) = P2pNode::start(test_config()).await.unwrap();

    node_a
        .send_direct(node_b.peer_id(), envelope(b"conv-ghost"))
        .await
        .unwrap();

    wait_for(&mut events_a, |e| {
        matches!(e, NodeEvent::DirectFailed { to, .. } if *to == node_b.peer_id())
    }, Duration::from_secs(15)).await;

    node_a.stop().await;
    node_b.stop().await;
}

#[tokio::test]
async fn gossipsub_message_roundtrip() {
    let (node_a, mut events_a) = P2pNode::start(test_config()).await.unwrap();
    let (node_b, mut events_b) = P2pNode::start(test_config()).await.unwrap();

    let topic = presidium_network::topics::group_topic(b"conv-gossip").unwrap();
    node_a.subscribe(topic.clone()).await.unwrap();
    node_b.subscribe(topic.clone()).await.unwrap();

    wait_listening(&mut events_b, &node_b).await;

    let addr_b = tcp_addr(node_b.listen_addrs().await)
        .with(Protocol::P2p(node_b.peer_id()));
    node_a.dial(addr_b).await.unwrap();

    wait_for(&mut events_a, |e| {
        matches!(e, NodeEvent::PeerConnected { peer } if *peer == node_b.peer_id())
    }, Duration::from_secs(10)).await;

    // Let gossipsub exchange subscriptions on the next heartbeat.
    sleep(Duration::from_secs(2)).await;

    let envelope = envelope(b"conv-gossip");
    node_a.publish(topic.clone(), envelope.clone()).await.unwrap();

    let received = wait_for(&mut events_b, |e| {
        matches!(e, NodeEvent::GossipMessage { topic: t, envelope: env, .. } if *t == topic.hash() && env == &envelope)
    }, Duration::from_secs(10)).await;
    match received {
        NodeEvent::GossipMessage { from, .. } => assert_eq!(from, node_a.peer_id()),
        other => panic!("unexpected event: {other:?}"),
    }

    node_a.stop().await;
    node_b.stop().await;
}
