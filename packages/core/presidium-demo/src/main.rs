//! Presidium E2E demo.
//!
//! Two processes run a full W2-W4 stack: PQXDH + Double Ratchet 1:1 chats
//! over libp2p request-response, SenderKeys group chats over GossipSub, and
//! everything persisted in an encrypted sqleet database.
//!
//! Usage:
//!   presidium-demo --role responder --dir data/responder
//!   presidium-demo --role initiator --dir data/initiator --peer <multiaddr>

mod group;
mod session;
mod store;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use libp2p::{Multiaddr, PeerId};
use presidium_network::{KadMode, NodeConfig, NodeEvent, P2pNode};
use presidium_storage::models::{MessageDirection, MessageStatus};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;
use rand::Rng;use crate::group::{short_peer, GroupChat};
use crate::session::{ChatSession, InitiatorHandshake, ResponderHandshake};
use crate::store::NodeStore;

/// Demo role: who performs the PQXDH handshake as initiator.
#[derive(Clone, Copy, ValueEnum)]
enum Role {
    Initiator,
    Responder,
}

/// Command line options.
#[derive(Parser)]
#[command(name = "presidium-demo", about = "E2E encrypted messenger demo")]
struct Cli {
    /// PQXDH role of this node.
    #[arg(long, value_enum)]
    role: Role,
    /// Node data directory (identity, session, history).
    #[arg(long)]
    dir: PathBuf,
    /// Peer to dial: /ip4/.../tcp/.../p2p/<peer-id> (initiator only).
    #[arg(long)]
    peer: Option<String>,
}

/// Application state shared by the event loop.
pub struct App {
    store: NodeStore,
    node: P2pNode,
    events: mpsc::Receiver<NodeEvent>,
    initiator: Option<InitiatorHandshake>,
    responder: Option<ResponderHandshake>,
    session: Option<ChatSession>,
    group: GroupChat,
    /// The remote peer (learned from the dial or the first inbound message).
    peer: Option<PeerId>,
    last_outgoing: Option<i64>,
}

impl App {
    fn print_banner(&self) {
        println!("=== presidium demo ===");
        println!("device id : {}", self.store.device_id);
        println!("peer id   : {}", self.node.peer_id());
        println!("identity  : {}", hex::encode(&self.store.identity_public().classical[..8]));
    }
}

/// Entry point: run the async main on a thread with a large stack.
///
/// Debug builds of the post-quantum crypto need several MiB of stack
/// (ML-DSA keygen frames), so the 1 MiB Windows default for the main
/// thread would overflow.
fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("presidium-demo".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(run_demo)
        .expect("spawn demo thread")
        .join()
        .map_err(|_| anyhow::anyhow!("demo thread panicked"))
        .and_then(std::convert::identity)
}

fn run_demo() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(16 * 1024 * 1024)
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(demo_main())
}

async fn demo_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "presidium_demo=info,presidium_network=warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let config = NodeConfig {
        listen: vec!["/ip4/0.0.0.0/tcp/0".parse()?],
        mdns_enabled: false,
        auto_dial: false,
        kad_mode: KadMode::Disabled,
        request_timeout: Duration::from_secs(30),
        ..NodeConfig::default()
    };
    let (node, events) = P2pNode::start(config).await?;

    let store = NodeStore::open(&cli.dir)?;
    let mut app = App {
        store,
        node,
        events,
        initiator: None,
        responder: None,
        session: None,
        group: GroupChat::new()?,
        peer: None,
        last_outgoing: None,
    };
    app.print_banner();

    // Subscribe to the demo group topic.
    app.node.subscribe(app.group.topic().clone()).await?;

    match cli.role {
        Role::Responder => {
            let prekey = app.store.prekey()?;
            let responder = ResponderHandshake::new(app.store.identity.clone(), prekey);
            println!("[responder] waiting for the initiator…");
            app.responder = Some(responder);
            let addr = app.node.listen_addrs().await;
            println!("[responder] listening: {addr:?}");
            let dialable = dialable_address(&addr, app.node.peer_id());
            println!("[responder] connect with:");
            println!("  presidium-demo --role initiator --dir <initiator-dir> --peer {dialable}");
        }
        Role::Initiator => {
            let peer_addr: Multiaddr = cli
                .peer
                .context("--peer is required for the initiator")?
                .parse()?;
            let peer = peer_id_of(&peer_addr);
            app.peer = Some(peer);
            // Resume a persisted session with the responder, skipping the handshake.
            if let Some(session) = session::resume(&app.store, &app.store.device_id)? {
                println!("[initiator] resumed persisted session, skipping handshake");
                app.session = Some(session);
            }
            app.initiator = Some(InitiatorHandshake::new(
                app.store.identity.clone(),
                app.store.device_id.clone(),
                peer,
            ));
            app.node.dial(peer_addr).await?;
        }
    }

    run_loop(&mut app).await
}

/// The main event loop: stdin commands + node events.
async fn run_loop(app: &mut App) -> Result<()> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut handshake_started = false;

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line? else { break };
                let line = line.trim().to_string();
                if line.is_empty() { continue; }
                if !handle_command(app, &line).await? {
                    break;
                }
            }
            event = app.events.recv() => {
                let Some(event) = event else { break };
                if !handle_event(app, event, &mut handshake_started).await? {
                    break;
                }
            }
        }
    }

    // The node task is aborted on process exit; nothing to clean up.
    println!("bye");
    Ok(())
}

/// Handle an interactive command; returns false when the loop must exit.
async fn handle_command(app: &mut App, line: &str) -> Result<bool> {
    match line {
        "q" | "@quit" | "exit" => return Ok(false),
        "@info" => {
            app.print_banner();
            println!("session : {}", if app.session.is_some() { "established" } else { "none" });
            println!(
                "group   : {}",
                if app.group.sender.is_some() || app.group.receiver.is_some() {
                    "ready"
                } else {
                    "not ready"
                }
            );
            return Ok(true);
        }
        "@history" => {
            app.store.print_history(&app.store.device_id)?;
            app.store.print_history(&app.group.conversation_id)?;
            return Ok(true);
        }
        _ => {}
    }

    if let Some(text) = line.strip_prefix("@group ") {
        if app.group.sender.is_none() {
            println!("group sender keys not ready yet");
            return Ok(true);
        }
        app.group
            .publish(
                &app.node,
                &app.store.identity,
                &app.store.device_id,
                text.as_bytes(),
            )
            .await?;
        println!("[group] -> {text}");
        return Ok(true);
    }

    let Some(session) = app.session.as_mut() else {
        println!("no 1:1 session yet; wait for the handshake");
        return Ok(true);
    };
    let Some(peer) = app.peer else {
        println!("no remote peer known yet");
        return Ok(true);
    };
    let envelope = session.encrypt(&app.store.identity, &app.store.device_id, line.as_bytes())?;
    let header_json = String::from_utf8(envelope.nonce.to_vec())?;
    let row = app.store.insert_message(
        &session.conversation_id,
        message_id_bytes(envelope.timestamp),
        &app.store.identity_public(),
        &envelope.encrypted_payload,
        &header_json,
        MessageDirection::Outgoing,
    )?;
    app.last_outgoing = Some(row);
    app.node.send_direct(peer, envelope).await?;
    // Snapshot the ratchet so a restarted process can resume the chain without
    // re-deriving a stale root key (otherwise the next message's message-number
    // would desync against the peer).
    if let Some(session) = app.session.as_mut() {
        let _ = session.persist(&app.store);
    }
    println!("[1:1] -> {line}");
    Ok(true)
}

/// Handle a node event; returns false when the loop must exit.
async fn handle_event(
    app: &mut App,
    event: NodeEvent,
    handshake_started: &mut bool,
) -> Result<bool> {
    match event {
        NodeEvent::Listen { address } => {
            println!("[net] listening on {address}");
        }
        NodeEvent::PeerConnected { peer } => {
            println!("[net] connected to {}", short_peer(peer));
            if app.peer.is_none() {
                app.peer = Some(peer);
            }
            if app.initiator.is_some()
                && app.session.is_none()
                && !*handshake_started
            {
                *handshake_started = true;
                if let Some(initiator) = app.initiator.as_mut() {
                    initiator.request_bundle(&app.node).await?;
                }
            }
        }
        NodeEvent::PeerDiscovered { peer, .. } => {
            println!("[net] discovered {}", short_peer(peer));
        }
        NodeEvent::DirectMessage { from, envelope } => {
            handle_direct(app, from, envelope).await?;
        }
        NodeEvent::GossipMessage { from, envelope, .. } => {
            match app.group.decrypt(&envelope) {
                Ok(plaintext) => {
                    println!("[group] {}: {}", short_peer(from), String::from_utf8_lossy(&plaintext));
                    let sender = app
                        .session
                        .as_ref()
                        .map(|s| s.peer_identity.clone())
                        .unwrap_or_else(|| app.store.identity_public());
                    // Make sure the group conversation row exists so the group
                    // message row's FK into `conversations` is satisfied.
                    app.store
                        .upsert_conversation(&app.group.conversation_id, &sender, true)?;
                    app.store.insert_message(
                        &app.group.conversation_id,
                        message_id_bytes(envelope.timestamp),
                        &sender,
                        &envelope.encrypted_payload,
                        &String::from_utf8(envelope.nonce.to_vec())?,
                        MessageDirection::Incoming,
                    )?;
                }
                Err(e) => println!("[group] decrypt failed: {e}"),
            }
        }
        NodeEvent::DirectDelivered { to, status, .. } => {
            let ok = status.status == 1;
            if let Some(row) = app.last_outgoing.take() {
                app.store.update_message_status(
                    row,
                    if ok { MessageStatus::Delivered } else { MessageStatus::Failed },
                )?;
            }
            println!(
                "[1:1] delivered to {}: {}",
                short_peer(to),
                if ok { "ok" } else { "failed" }
            );
        }
        NodeEvent::DirectFailed { to, error } => {
            if let Some(row) = app.last_outgoing.take() {
                app.store.update_message_status(row, MessageStatus::Failed)?;
            }
            println!("[1:1] failed to {}: {error}", short_peer(to));
        }
        NodeEvent::PeerDisconnected { peer } => {
            println!("[net] disconnected {}", short_peer(peer));
        }
    }
    Ok(true)
}

/// Route an inbound direct message by its sync marker.
async fn handle_direct(
    app: &mut App,
    from: PeerId,
    envelope: presidium_proto::messages::NetworkEnvelope,
) -> Result<()> {
    if app.peer.is_none() {
        app.peer = Some(from);
    }
    let payload = &envelope.encrypted_payload;
    match payload.first().copied() {
        Some(session::MARKER_BUNDLE_REQ) => {
            let responder = app.responder.as_ref().context("bundle request on initiator")?;
            let bundle = responder.bundle()?;
            let reply = session::sync_envelope(
                &app.store.identity,
                &app.store.device_id,
                session::MARKER_BUNDLE,
                &serde_json::to_vec(&bundle)?,
            )?;
            app.node.send_direct(from, reply).await?;
        }
        Some(session::MARKER_BUNDLE) => {
            let bundle: presidium_crypto::identity::PreKeyBundle =
                serde_json::from_slice(&payload[1..]).context("parse bundle")?;
            let initiator = app.initiator.as_mut().context("bundle on responder")?;
            app.store
                .upsert_conversation(&app.store.device_id, &bundle.identity_key, false)?;
            initiator.send_prekey(&app.node, bundle).await?;
        }
        Some(session::MARKER_PREKEY) => {
            let conversation_id = String::from_utf8(envelope.sender_device_id.to_vec())
                .context("invalid sender device id")?;
            let responder = app.responder.as_mut().context("prekey on initiator")?;
            let (ratchet_public, chat) = responder.on_prekey(&payload[1..], &conversation_id)?;
            // on_prekey populated peer_identity; upsert the conversation first
            // so the session row's foreign key resolves.
            let peer_identity = responder
                .peer_identity
                .clone()
                .context("no peer identity after prekey")?;
            app.store
                .upsert_conversation(&conversation_id, &peer_identity, false)?;
            chat.persist(&app.store)?;
            app.session = Some(chat);
            let reply = session::sync_envelope(
                &app.store.identity,
                &app.store.device_id,
                session::MARKER_RATCHET_PUB,
                &ratchet_public,
            )?;
            app.node.send_direct(from, reply).await?;
            println!("[responder] session established with {}", short_peer(from));
        }
        Some(session::MARKER_RATCHET_PUB) => {
            let initiator = app.initiator.as_mut().context("ratchet pub on responder")?;
            let chat = initiator.establish(&payload[1..])?;
            // Conversation row must exist before the session row's FK.
            let peer_identity = initiator
                .peer_identity
                .clone()
                .context("no peer identity after establish")?;
            app.store.upsert_conversation(
                &app.store.device_id,
                &peer_identity,
                false,
            )?;
            chat.persist(&app.store)?;
            app.session = Some(chat);
            // Distribute the group sender key to the responder.
            let distribution = app.group.create_sender(&app.store.identity)?;
            let reply = session::sync_envelope(
                &app.store.identity,
                &app.store.device_id,
                session::MARKER_GROUP_KEY,
                &serde_json::to_vec(&distribution)?,
            )?;
            app.node.send_direct(from, reply).await?;
            // Greet the peer with the first ratchet-encrypted message.
            let greeting = format!("hello from {}", app.store.device_id);
            let envelope = app
                .session
                .as_mut()
                .unwrap()
                .encrypt(&app.store.identity, &app.store.device_id, greeting.as_bytes())?;
            app.node.send_direct(from, envelope).await?;
            // Snapshot the ratchet after the greeting so a restarted process
            // resumes the correct message-number chain.
            if let Some(session) = app.session.as_mut() {
                let _ = session.persist(&app.store);
            }
            println!("[initiator] session established with {}", short_peer(from));
        }
        Some(session::MARKER_GROUP_KEY) => {
            let distribution: group::GroupKeyDistribution =
                serde_json::from_slice(&payload[1..]).context("parse group key")?;
            let peer = app
                .session
                .as_ref()
                .map(|s| s.peer_identity.clone())
                .context("no session for group key")?;
            app.group.apply_group_key(distribution, &peer);
            println!("[responder] group key received, group ready");
        }
        _ => {
            // Regular encrypted chat message; resume the session if needed.
            let conversation_id = String::from_utf8(envelope.conversation_id.to_vec())?;
            if app.session.is_none() {
                if let Some(chat) = session::resume(&app.store, &conversation_id)? {
                    println!("[responder] resumed persisted session");
                    app.session = Some(chat);
                }
            }
            let session = app.session.as_mut().context("no session established")?;
            // Ensure the conversation row exists (e.g. when the session was
            // resumed in-memory) so the message row's FK is satisfied.
            app.store
                .upsert_conversation(&conversation_id, &session.peer_identity, false)?;
            let plaintext = session.decrypt(&envelope)?;
            session.persist(&app.store)?;
            println!("[1:1] {}: {}", short_peer(from), String::from_utf8_lossy(&plaintext));
            let header_json = String::from_utf8(envelope.nonce.to_vec())?;
            app.store.insert_message(
                &conversation_id,
                message_id_bytes(envelope.timestamp),
                &session.peer_identity,
                &envelope.encrypted_payload,
                &header_json,
                MessageDirection::Incoming,
            )?;
        }
    }
    Ok(())
}

/// Build a globally-unique message id: timestamp + random nonce, so a fast
/// restart never collides with the `UNIQUE(conversation_id, message_id)` index.
fn message_id_bytes(timestamp: u64) -> Vec<u8> {
    let mut id = timestamp.to_le_bytes().to_vec();
    id.extend_from_slice(&rand::rng().next_u32().to_le_bytes());
    id
}

/// Extract the peer id from a multiaddr with a /p2p/ suffix.
fn peer_id_of(addr: &Multiaddr) -> PeerId {
    addr.iter()
        .filter_map(|p| match p {
            multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .next()
        .expect("--peer must carry a /p2p/<peer-id> suffix")
}

/// Build a dialable loopback address: replace 0.0.0.0 and append /p2p/<peer>.
fn dialable_address(addrs: &[Multiaddr], peer: PeerId) -> Multiaddr {
    let addr = addrs
        .iter()
        .find(|a| a.iter().any(|p| matches!(p, multiaddr::Protocol::Tcp(_))))
        .cloned()
        .unwrap_or_else(|| "/ip4/127.0.0.1/tcp/0".parse().expect("static addr"));
    let text = addr
        .to_string()
        .replace("/ip4/0.0.0.0", "/ip4/127.0.0.1");
    format!("{text}/p2p/{peer}")
        .parse()
        .expect("dialable address")
}
