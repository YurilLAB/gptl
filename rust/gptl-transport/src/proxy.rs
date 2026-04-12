//! SOCKS5 → GPTL circuit proxy.
//!
//! `GptlProxy::run` listens for SOCKS5 connections, builds a circuit
//! to relay(s) from the bootstrap directory, and splices data bidirectionally.
//!
//! # Multi-hop support
//!
//! When `ProxyConfig::hop_count >= 2` and at least two relays are available,
//! `handle_connection` calls `Circuit::extend` to build a 2-hop path.

use crate::{
    bootstrap::BootstrapConfig,
    circuit::Circuit,
    handshake::{client_finish, client_initiate},
    relay_conn::RelayConn,
    socks5,
    TransportError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Configuration for the GPTL SOCKS5 proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on for SOCKS5 connections (e.g. 127.0.0.1:1080)
    pub listen_addr: SocketAddr,
    /// Bootstrap relay directory
    pub bootstrap: Arc<BootstrapConfig>,
    /// Number of hops to build (1 = single-hop, 2 = two-hop).  Max 2 for now.
    pub hop_count: usize,
}

impl ProxyConfig {
    /// Create a single-hop proxy config.
    pub fn new_single_hop(listen_addr: SocketAddr, bootstrap: Arc<BootstrapConfig>) -> Self {
        Self { listen_addr, bootstrap, hop_count: 1 }
    }
}

/// Run the GPTL SOCKS5 proxy.
///
/// This function runs forever (until the process exits or a fatal listener error).
pub async fn run(config: ProxyConfig) -> Result<(), TransportError> {
    let listener = TcpListener::bind(config.listen_addr).await
        .map_err(|e| TransportError::Io(format!("bind {}: {}", config.listen_addr, e)))?;

    info!("GPTL SOCKS5 proxy listening on {}", config.listen_addr);

    loop {
        // Bug 3 fix: continue on transient accept() errors, only propagate fatal ones.
        let (client_stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) if is_transient_io_error(&e) => {
                debug!("transient accept error: {}", e);
                continue;
            }
            Err(e) => return Err(TransportError::Io(format!("accept failed: {}", e))),
        };
        debug!("SOCKS5 connection from {}", peer);

        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, cfg).await {
                match e {
                    TransportError::ConnectionClosed => {}
                    other => warn!("connection from {} ended: {}", peer, other),
                }
            }
        });
    }
}

/// Handle one SOCKS5 client connection.
async fn handle_connection(
    mut client: TcpStream,
    config: ProxyConfig,
) -> Result<(), TransportError> {
    // ── Step 1: SOCKS5 negotiation ────────────────────────────────────────────
    let request = socks5::negotiate(&mut client).await?;
    debug!("SOCKS5 CONNECT {}:{}", request.host, request.port);

    // ── Step 2: Build circuit to relay1 ──────────────────────────────────────
    let relay_desc = config.bootstrap.pick_random()
        .ok_or_else(|| TransportError::Bootstrap("no relays available".into()))?
        .clone();

    let relay_addr   = relay_desc.socket_addr()?;
    let relay_pubkey = relay_desc.pubkey_bytes()?;

    let mut relay_conn = match RelayConn::connect(relay_addr).await {
        Ok(c) => c,
        Err(e) => {
            socks5::send_general_failure(&mut client).await;
            return Err(e);
        }
    };

    // Generate a random circuit ID (non-zero, odd by client convention)
    let circuit_id = {
        use rand::Rng;
        let mut id: u32 = rand::thread_rng().gen();
        if id == 0 { id = 1; }
        if id & 1 == 0 { id += 1; }
        id
    };

    // Handshake with relay1
    let (create_cell, pending) = client_initiate(circuit_id, &relay_pubkey)?;
    relay_conn.send(&create_cell).await?;

    let created = relay_conn.recv().await?;
    let keys = match client_finish(pending, &created) {
        Ok(k) => k,
        Err(e) => {
            socks5::send_general_failure(&mut client).await;
            return Err(e);
        }
    };
    debug!("handshake complete with relay1 '{}'", relay_desc.nickname);

    let mut circuit = Circuit::new(circuit_id, keys, relay_conn);

    // ── Step 2b: Optionally extend to relay2 ─────────────────────────────────
    if config.hop_count >= 2 && config.bootstrap.relays.len() >= 2 {
        let relay2 = config.bootstrap
            .pick_relay_excluding(&relay_desc.nickname)
            .ok_or_else(|| TransportError::Bootstrap("no relay2 available for multi-hop".into()))?
            .clone();

        if let Err(e) = circuit.extend(&relay2).await {
            socks5::send_general_failure(&mut client).await;
            return Err(e);
        }
        debug!("circuit {} extended to relay2 '{}'", circuit_id, relay2.nickname);
    }

    // ── Step 3: Open a stream to the destination ──────────────────────────────
    let mut stream = circuit.open_stream(&request.host, request.port).await?;

    // Bug 1 fix: use select! to race circuit stepping against wait_connected(),
    // instead of the double-timeout polling anti-pattern.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        async {
            loop {
                tokio::select! {
                    result = circuit.step() => {
                        result?;
                    }
                    result = stream.wait_connected() => {
                        return result;
                    }
                }
            }
        },
    )
    .await
    .map_err(|_| TransportError::Protocol("relay connect timed out".into()))??;

    // Tell the SOCKS5 client we're connected
    socks5::send_success(&mut client).await;
    info!(
        "circuit {} stream {} → {}:{}",
        circuit_id, stream.stream_id, request.host, request.port
    );

    // ── Step 4: Splice data bidirectionally ───────────────────────────────────
    splice(client, stream, circuit).await
}

/// Bidirectionally forward data between the SOCKS5 client and the circuit stream.
///
/// Bug 2 fix: `circuit.step()` runs in a separate task so it can always make
/// progress, removing the deadlock where `stream.read_data()` could only be
/// satisfied by `step()` but `step()` was competing in the same `select!`.
async fn splice(
    mut client: TcpStream,
    mut stream: crate::circuit::CircuitStream,
    mut circuit: Circuit,
) -> Result<(), TransportError> {
    let (circuit_error_tx, mut circuit_error_rx) = mpsc::channel::<TransportError>(1);

    // Run circuit.step() in its own task so it can always make progress.
    tokio::spawn(async move {
        loop {
            match circuit.step().await {
                Ok(()) => {}
                Err(TransportError::CircuitClosed) => break,
                Err(TransportError::ConnectionClosed) => break,
                Err(e) => {
                    let _ = circuit_error_tx.send(e).await;
                    break;
                }
            }
        }
        circuit.destroy().await;
    });

    let mut client_buf = vec![0u8; 16384];

    loop {
        tokio::select! {
            // Error from the circuit background task
            Some(e) = circuit_error_rx.recv() => {
                return Err(e);
            }
            // Data from SOCKS5 client → send through circuit
            n = client.read(&mut client_buf) => {
                match n {
                    Ok(0) | Err(_) => {
                        let _ = stream.close().await;
                        break;
                    }
                    Ok(n) => {
                        stream.write(&client_buf[..n]).await?;
                    }
                }
            }
            // Data from circuit → send to SOCKS5 client
            data = stream.read_data() => {
                match data {
                    Some(d) => {
                        if client.write_all(&d).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

/// Returns `true` for transient OS-level accept() errors that should not
/// terminate the listener (e.g. ECONNABORTED, EMFILE on some platforms).
fn is_transient_io_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | TimedOut | WouldBlock
    )
}
