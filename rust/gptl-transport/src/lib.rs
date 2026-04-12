//! gptl-transport — Phase 1 single-hop anonymized transport.
//!
//! Implements:
//! - Fixed 512-byte cell protocol (traffic-size resistant)
//! - ntor-lite handshake (X25519 + HKDF-SHA256)
//! - ChaCha20Poly1305 per-circuit cell encryption
//! - SOCKS5 proxy front-end (RFC 1928)
//! - Relay node (CREATE/CREATED handshake + RELAY cell forwarding)
//! - Bootstrap directory (JSON relay descriptor list)

pub mod bootstrap;
pub mod cell;
pub mod circuit;
pub mod crypto;
pub mod handshake;
pub mod proxy;
pub mod relay_conn;
pub mod socks5;

pub use bootstrap::{BootstrapConfig, RelayDescriptor};
pub use cell::{Cell, CellType, RelayCell, RelayCommand};
pub use circuit::{Circuit, CircuitStream};
pub use crypto::{CellCipher, CircuitCiphers, RelayCiphers};
pub use handshake::{RelayStaticKey, SessionKeys};
pub use proxy::{ProxyConfig, run as run_proxy};
pub use relay_conn::RelayConn;
pub use socks5::ConnectRequest;

/// Top-level error type for the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Low-level I/O failure (TCP read/write, bind, connect).
    #[error("I/O error: {0}")]
    Io(String),

    /// Protocol violation (unexpected cell type, malformed data, etc.).
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Handshake failure (key confirmation mismatch, wrong fingerprint, etc.).
    #[error("Handshake error: {0}")]
    Handshake(String),

    /// Cryptographic failure (encryption/decryption error, counter exhausted).
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// SOCKS5 negotiation error.
    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    /// Bootstrap directory error (missing file, invalid JSON, bad pubkey).
    #[error("Bootstrap error: {0}")]
    Bootstrap(String),

    /// The circuit has been destroyed (received DESTROY cell or connection dropped).
    #[error("Circuit closed")]
    CircuitClosed,

    /// The underlying TCP connection closed cleanly (EOF).
    #[error("Connection closed")]
    ConnectionClosed,
}
