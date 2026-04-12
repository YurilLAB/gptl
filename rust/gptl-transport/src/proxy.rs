//! SOCKS5 → GPTL circuit proxy.
//!
//! `GptlProxy::run` listens for SOCKS5 connections, builds a single-hop circuit
//! to a relay from the bootstrap directory, and splices data bidirectionally.

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
use tracing::{debug, info, warn};

/// Configuration for the GPTL SOCKS5 proxy.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on for SOCKS5 connections (e.g. 127.0.0.1:1080)
    pub listen_addr: SocketAddr,
    /// Bootstrap relay directory
    pub bootstrap: Arc<BootstrapConfig>,
}

/// Run the GPTL SOCKS5 proxy.
///
/// This function runs forever (until the process exits or the listener errors).
pub async fn run(config: ProxyConfig) -> Result<(), TransportError> {
    let listener = TcpListener::bind(config.listen_addr).await
        .map_err(|e| TransportError::Io(format!("bind {}: {}", config.listen_addr, e)))?;

    info!("GPTL SOCKS5 proxy listening on {}", config.listen_addr);

    loop {
        let (client_stream, peer) = listener.accept().await
            .map_err(|e| TransportError::Io(format!("accept: {}", e)))?;
        debug!("SOCKS5 connection from {}", peer);

        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client_stream, cfg).await {
                // Log but do not crash the proxy for per-connection errors
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

    // ── Step 2: Build circuit to a relay ─────────────────────────────────────
    let relay_desc = config.bootstrap.pick_random()
        .ok_or_else(|| TransportError::Bootstrap("no relays available".into()))?
        .clone();

    let relay_addr = relay_desc.socket_addr()?;
    let relay_pubkey = relay_desc.pubkey_bytes()?;

    let mut relay_conn = match RelayConn::connect(relay_addr).await {
        Ok(c) => c,
        Err(e) => {
            socks5::send_general_failure(&mut client).await;
            return Err(e);
        }
    };

    // Generate a random circuit ID (non-zero, client uses odd IDs by convention)
    let circuit_id = {
        use rand::Rng;
        let mut id: u32 = rand::thread_rng().gen();
        if id == 0 { id = 1; }
        if id % 2 == 0 { id += 1; }
        id
    };

    // Handshake with relay
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
    debug!("handshake complete with relay {}", relay_desc.nickname);

    let mut circuit = Circuit::new(circuit_id, keys, relay_conn);

    // ── Step 3: Open a stream to the destination ──────────────────────────────
    let mut stream = circuit.open_stream(&request.host, request.port).await?;

    // Drive the circuit to send the BEGIN cell and receive CONNECTED/FAILED
    // We need to pump the circuit until we get the connection result.
    let connect_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        async {
            loop {
                circuit.step().await?;
                // step delivers inbound cells to stream's channel
                // try to get the connection result without blocking
                if let Ok(result) = tokio::time::timeout(
                    std::time::Duration::from_millis(0),
                    stream.wait_connected(),
                ).await {
                    return result;
                }
            }
        },
    ).await;

    match connect_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            socks5::send_connection_refused(&mut client).await;
            return Err(e);
        }
        Err(_timeout) => {
            socks5::send_general_failure(&mut client).await;
            return Err(TransportError::Protocol("relay connect timed out".into()));
        }
    }

    // Tell the SOCKS5 client we're connected
    socks5::send_success(&mut client).await;
    info!("circuit {} stream {} → {}:{}", circuit_id, stream.stream_id, request.host, request.port);

    // ── Step 4: Splice data bidirectionally ───────────────────────────────────
    splice(client, stream, circuit).await
}

/// Bidirectionally forward data between the SOCKS5 client and the circuit stream.
async fn splice(
    mut client: TcpStream,
    mut stream: crate::circuit::CircuitStream,
    mut circuit: Circuit,
) -> Result<(), TransportError> {
    let mut client_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
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

            // Drive the circuit (send/receive encrypted cells)
            result = circuit.step() => {
                if let Err(TransportError::CircuitClosed) = result {
                    break;
                }
                result?;
            }
        }
    }

    circuit.destroy().await;
    Ok(())
}
