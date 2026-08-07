# Presidium Messenger

> **P2P End-to-End Encrypted Messenger** — No servers, no metadata, pure privacy.

## Overview

Presidium is a peer-to-peer messenger with end-to-end encryption, local-first storage, and no central servers. Built with modern cryptography (PQXDH, Double Ratchet) and libp2p for decentralized communication.

## Features

- **1:1 Chats** — Signal Protocol (PQXDH + Double Ratchet)
- **Group Chats** — Sender Keys (Megolm-style) for efficient E2EE
- **Channels** — Broadcast to unlimited followers via GossipSub
- **Stories** — 24h ephemeral content with viewer tracking
- **Feed** — Algorithmic timeline from followed channels/groups
- **Voice Messages** — Opus encrypted, waveform UI
- **Video Circles** — 60s circular video, front camera
- **Multi-device** — P2P sync via CRDTs (Yrs)
- **Offline-first** — Local SQLCipher storage, sync on reconnect
- **Push Notifications** — Optional self-hosted gateway (encrypted tokens)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Clients: React Native (Expo) + Tauri v2 + Web (PWA)       │
├─────────────────────────────────────────────────────────────┤
│  Shared Core (Rust → WASM/UniFFI):                         │
│  ├── Crypto: PQXDH, Double Ratchet, ML-KEM-1024, ML-DSA-87 │
│  ├── Storage: SQLCipher + Argon2id + Yrs CRDT              │
│  ├── Network: libp2p (Noise XX, WebRTC, QUIC, GossipSub)   │
│  └── Sync: Event sourcing + Merkle DAG                      │
├─────────────────────────────────────────────────────────────┤
│  P2P Network: mDNS + DHT + Rendezvous + Volunteer Relays   │
└─────────────────────────────────────────────────────────────┘
```

## Stack

| Layer | Technology |
|-------|------------|
| Core | Rust 2021 → WASM (UniFFI) |
| Mobile | Expo SDK 51 + React Native 0.76 + NativeWind v4 |
| Desktop | Tauri v2 + React 19 + shadcn/ui |
| Crypto | ml-kem-1024, ml-dsa-87, x25519, ed25519, chacha20poly1305 |
| Storage | SQLCipher (AES-256) + Argon2id + Yrs CRDT |
| Network | libp2p 0.55+ (Noise XX, WebRTC, QUIC, GossipSub v1.2) |
| Discovery | DNS bootstrap (dnsaddr) + mDNS + Kademlia DHT |
| Build | Turborepo + Cargo workspace + EAS Build |

## Quick Start

```bash
# Prerequisites
# - Node.js 20+, pnpm 9+, Rust 1.78+
# - Android Studio / Xcode for mobile
# - Tauri prerequisites for desktop

# Install dependencies
pnpm install

# Build Rust core (generates WASM + bindings)
cd packages/core && cargo build --release

# Generate TypeScript types
pnpm turbo run generate

# Start development
pnpm dev              # All apps
pnpm --filter mobile dev   # Mobile only
pnpm --filter desktop dev  # Desktop only
```

## Project Structure

```
presidium/
├── apps/
│   ├── mobile/          # Expo React Native app
│   ├── desktop/         # Tauri v2 desktop app
│   └── web/             # Vite + React PWA
├── packages/
│   ├── core/            # Rust workspace (7 crates)
│   │   ├── presidium-crypto/      # PQXDH, Double Ratchet
│   │   ├── presidium-storage/     # SQLCipher, Yrs CRDT
│   │   ├── presidium-network/     # libp2p node
│   │   ├── presidium-sync/        # Event store, sync engine
│   │   ├── presidium-media/       # Encrypted media handling
│   │   ├── presidium-proto/       # Protobuf definitions
│   │   └── presidium-ffi/         # UniFFI bindings
│   ├── ui/              # Shared React components
│   └── types/           # Generated TypeScript types
├── tools/relay/         # Optional push gateway
└── docs/                # Architecture, crypto specs
```

## Security

- **Post-Quantum Ready**: PQXDH with ML-KEM-1024 + ML-DSA-87
- **Forward Secrecy**: Double Ratchet per conversation
- **Local-First**: Encrypted SQLite (SQLCipher) on device
- **No Metadata**: No central server, minimal relay metadata
- **Verifiable**: Safety numbers, device verification, audit log

## License

GPL-3.0-only — See [LICENSE](LICENSE) for details.

## Author

**Sergey Presidium** — presidium_messanger@internet.ru

## Contributing

See [CONTRIBUTING.md](docs/contributing.md) for guidelines.

---

**Status**: Phase 0 — Foundation (Weeks 1-4)