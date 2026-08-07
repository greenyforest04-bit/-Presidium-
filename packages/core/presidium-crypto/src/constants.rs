//! Cryptographic constants for Presidium

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 2;

/// Key sizes (bytes)
/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 private key (seed) size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;
/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// X25519 public key size in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
/// X25519 private key size in bytes
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;
/// X25519 shared secret size in bytes
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM-1024 encapsulation (public) key size in bytes
pub const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
/// Size of the canonical ML-KEM-1024 seed that serializes a decapsulation key.
pub const ML_KEM_1024_PRIVATE_KEY_SIZE: usize = 64;
/// ML-KEM-1024 ciphertext size in bytes
pub const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;
/// ML-KEM-1024 shared secret size in bytes
pub const ML_KEM_1024_SHARED_SECRET_SIZE: usize = 32;

/// ML-DSA-87 public key size in bytes
pub const ML_DSA_87_PUBLIC_KEY_SIZE: usize = 2592;
/// Size of the ML-DSA-87 seed (FIPS 204: xi is 32 bytes) that serializes a signing key.
pub const ML_DSA_87_PRIVATE_KEY_SIZE: usize = 32;
/// ML-DSA-87 signature size in bytes
pub const ML_DSA_87_SIGNATURE_SIZE: usize = 4627;

/// ChaCha20-Poly1305 key size in bytes
pub const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size in bytes
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
/// ChaCha20-Poly1305 authentication tag size in bytes
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

/// AES-256-GCM key size in bytes
pub const AES_256_GCM_KEY_SIZE: usize = 32;
/// AES-256-GCM nonce size in bytes
pub const AES_256_GCM_NONCE_SIZE: usize = 12;
/// AES-256-GCM authentication tag size in bytes
pub const AES_256_GCM_TAG_SIZE: usize = 16;

/// HKDF output size in bytes
pub const HKDF_OUTPUT_SIZE: usize = 32;
/// HMAC-SHA256 output size in bytes
pub const HMAC_SHA256_SIZE: usize = 32;

/// Ratchet constants
/// Double Ratchet root key size in bytes
pub const ROOT_KEY_SIZE: usize = 32;
/// Chain key size in bytes
pub const CHAIN_KEY_SIZE: usize = 32;
/// Message key size in bytes
pub const MESSAGE_KEY_SIZE: usize = 32;
/// Maximum skipped message keys kept per chain
pub const MAX_SKIP_MESSAGES: usize = 1000;
/// Maximum stored message keys per session
pub const MAX_MESSAGE_KEYS: usize = 2000;

/// PQXDH constants
/// Combined Ed25519 + ML-DSA-87 signature size in bytes
pub const PREKEY_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE + ML_DSA_87_SIGNATURE_SIZE;
/// Signed prekey rotation interval in days
pub const SIGNED_PREKEY_ROTATION_DAYS: u64 = 7;
/// Number of one-time prekeys published per bundle
pub const ONETIME_PREKEY_COUNT: usize = 100;
/// One-time prekey replenishment threshold
pub const ONETIME_PREKEY_THRESHOLD: usize = 20;

/// Argon2id parameters (OWASP 2023 recommendations)
/// Argon2id memory usage in KiB
pub const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MB
/// Argon2id iteration count
pub const ARGON2_ITERATIONS: u32 = 3;
/// Argon2id parallelism (threads)
pub const ARGON2_PARALLELISM: u32 = 4;
/// Argon2id output size in bytes
pub const ARGON2_OUTPUT_SIZE: usize = 32;
/// Argon2id salt size in bytes
pub const ARGON2_SALT_SIZE: usize = 16;

/// Media encryption
/// Media key size in bytes
pub const MEDIA_KEY_SIZE: usize = 32;
/// Encrypted media chunk size in bytes
pub const MEDIA_CHUNK_SIZE: usize = 1_048_576; // 1 MB
/// Media nonce size in bytes
pub const MEDIA_NONCE_SIZE: usize = 12;

/// Message format
/// Fixed message header size in bytes (version + flags + ephemeral key + counter)
pub const MESSAGE_HEADER_SIZE: usize = 64;
/// Message authentication code size in bytes
pub const MAC_SIZE: usize = 32;

/// Session limits
/// Maximum session age before rotation
pub const MAX_SESSION_AGE_DAYS: u64 = 30;
/// Maximum messages per session before rotation
pub const MAX_MESSAGES_PER_SESSION: u64 = 1_000_000;
/// Message count triggering key rotation
pub const KEY_ROTATION_MESSAGE_COUNT: u64 = 1000;
/// Days after which keys rotate
pub const KEY_ROTATION_DAYS: u64 = 7;

/// Network
/// libp2p Noise handshake protocol name
pub const NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// GossipSub protocol ID
pub const GOSSIPSUB_PROTOCOL_ID: &str = "/presidium/1.0.0/gossipsub";
/// Kademlia DHT protocol ID
pub const DHT_PROTOCOL_ID: &str = "/presidium/1.0.0/kad";
/// Rendezvous protocol ID
pub const RENDEZVOUS_PROTOCOL_ID: &str = "/presidium/1.0.0/rendezvous";

/// Backup
/// Backup file format version
pub const BACKUP_VERSION: u32 = 1;
/// Backup KDF scrypt cost parameter N
pub const BACKUP_SCRYPT_N: u32 = 32768;
/// Backup KDF scrypt block size parameter r
pub const BACKUP_SCRYPT_R: u32 = 8;
/// Backup KDF scrypt parallelization parameter p
pub const BACKUP_SCRYPT_P: u32 = 1;
/// Backup encryption key size in bytes
pub const BACKUP_KEY_SIZE: usize = 32;
