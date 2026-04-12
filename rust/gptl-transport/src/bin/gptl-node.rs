//! GPTL relay node — accepts client circuits and proxies data to destinations.
//!
//! # Usage
//!
//!   gptl-node [OPTIONS]
//!
//! # Options
//!
//!   --key <PATH>             Path to private key file (hex, 32 bytes).
//!                             If absent, a new key is generated (ephemeral).
//!   --listen <ADDR>          Address to accept connections on (default: 0.0.0.0:9001)
//!   --nickname <NAME>        Human-readable relay name (default: hostname)
//!   --print-descriptor       Print a JSON relay descriptor and exit
//!   --log <LEVEL>            Log level: error|warn|info|debug|trace (default: info)

use gptl_transport::{
    bootstrap::{BootstrapConfig, RelayDescriptor},
    cell::{
        Cell, CellType, RelayCell, RelayCommand,
        CELL_PAYLOAD_LEN, CELL_SIZE, RELAY_INNER_CT_LEN, RELAY_INNER_PLAINTEXT_LEN, RELAY_MAX_DATA,
    },
    crypto::RelayCiphers,
    handshake::{relay_respond, RelayStaticKey},
    relay_conn::RelayConn,
    TransportError,
};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, warn};

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    init_logging(&args.log_level);

    let static_key = load_or_generate_key(args.key_path.as_deref());
    info!("relay fingerprint: {}", hex::encode(static_key.fingerprint));
    info!("relay pubkey:      {}", hex::encode(static_key.public));

    if args.print_descriptor {
        let desc = RelayDescriptor {
            nickname: args.nickname.clone(),
            address: format!("{}:{}", public_ip_hint(), args.listen.port()),
            pubkey_hex: hex::encode(static_key.public),
        };
        let config = BootstrapConfig { relays: vec![desc] };
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        return;
    }

    if let Some(ref path) = args.key_path {
        if !path.exists() {
            persist_key(&static_key, path);
        }
    }

    let listener = TcpListener::bind(args.listen).await.unwrap_or_else(|e| {
        eprintln!("error: bind {}: {}", args.listen, e);
        std::process::exit(1);
    });
    info!("GPTL relay '{}' listening on {}", args.nickname, args.listen);

    let static_key = Arc::new(static_key);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => { error!("accept: {}", e); continue; }
        };
        debug!("connection from {}", peer);

        let key = Arc::clone(&static_key);
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, peer, key).await {
                match e {
                    TransportError::ConnectionClosed | TransportError::CircuitClosed => {}
                    other => warn!("client {} ended: {}", peer, other),
                }
            }
        });
    }
}

// ── Per-client handler ────────────────────────────────────────────────────────

async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    static_key: Arc<RelayStaticKey>,
) -> Result<(), TransportError> {
    let _ = stream.set_nodelay(true);
    let mut conn = RelayConn::new(stream);

    // Perform handshake
    let create = conn.recv().await?;
    if !matches!(create.cell_type, CellType::Create) {
        return Err(TransportError::Protocol(format!(
            "expected CREATE, got {:?}", create.cell_type
        )));
    }

    let circuit_id = create.circuit_id;
    let (created, keys) = relay_respond(&create, &static_key)?;
    conn.send(&created).await?;
    debug!("circuit {} established with {}", circuit_id, peer);

    let ciphers = RelayCiphers::new(&keys.forward_key, &keys.backward_key);
    relay_circuit(conn, circuit_id, ciphers).await
}

// ── Circuit relay logic ───────────────────────────────────────────────────────

/// Destination write-half plus a channel to signal it to stop.
struct OutboundConn {
    write_half: tokio::net::tcp::OwnedWriteHalf,
}

/// Drive the relay side of an established circuit.
///
/// Architecture:
///   reader_task  reads raw 512-byte cells → cell_rx channel → main loop
///   writer_task  receives raw 512-byte frames from write_tx → writes to client TCP
///   dest_tasks   read from destination TCP → dest_rx channel → main loop
///   main loop    decrypts inbound cells, encrypts outbound cells, routes data
async fn relay_circuit(
    conn: RelayConn,
    circuit_id: u32,
    mut ciphers: RelayCiphers,
) -> Result<(), TransportError> {
    let tcp = conn.into_inner();
    let (mut read_half, write_half) = tcp.into_split();

    // Channels
    let (cell_tx, mut cell_rx) = mpsc::channel::<Result<Cell, TransportError>>(64);
    let (write_tx, mut write_rx) = mpsc::channel::<[u8; CELL_SIZE]>(256);
    let (dest_tx, mut dest_rx) = mpsc::channel::<(u16, Vec<u8>)>(256);

    // Reader task: reads raw cells from client TCP → cell_rx
    tokio::spawn(async move {
        loop {
            let mut buf = [0u8; CELL_SIZE];
            let result = match read_half.read_exact(&mut buf).await {
                Ok(_) => Cell::from_bytes(&buf),
                Err(e) => Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    TransportError::ConnectionClosed
                } else {
                    TransportError::Io(format!("read: {}", e))
                }),
            };
            let done = result.is_err();
            if cell_tx.send(result).await.is_err() || done {
                break;
            }
        }
    });

    // Writer task: writes raw cell bytes to client TCP
    let mut write_half = write_half;
    tokio::spawn(async move {
        while let Some(bytes) = write_rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    });

    // Open stream map
    let streams: Arc<Mutex<HashMap<u16, OutboundConn>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Main select loop
    let result = run_relay_loop(
        circuit_id,
        &mut ciphers,
        &mut cell_rx,
        &write_tx,
        &mut dest_rx,
        dest_tx,
        Arc::clone(&streams),
    ).await;

    // Cleanup: clear outbound streams and send DESTROY
    streams.lock().await.clear();
    let destroy = Cell::new(circuit_id, CellType::Destroy);
    let _ = write_tx.send(destroy.to_bytes()).await;

    result
}

async fn run_relay_loop(
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    cell_rx: &mut mpsc::Receiver<Result<Cell, TransportError>>,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    dest_rx: &mut mpsc::Receiver<(u16, Vec<u8>)>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
) -> Result<(), TransportError> {
    // Phase 2: channels for relay2 communication.
    // relay2_inbound_tx is cloned into the reader task spawned by handle_extend.
    // relay2_inbound_rx receives inner ciphertext blobs forwarded from relay2.
    let (relay2_inbound_tx, mut relay2_inbound_rx) = mpsc::channel::<Vec<u8>>(64);
    // relay2_write_tx is set once RELAY_EXTEND completes successfully.
    let mut relay2_write_tx: Option<mpsc::Sender<[u8; CELL_SIZE]>> = None;

    // Tracks whether this relay is operating as an inner hop (relay2 mode).
    // Set true when the first CellType::RelayInner is received.
    let mut is_inner_hop = false;

    loop {
        tokio::select! {
            // Inbound: cell from client (or relay1 if we are relay2)
            maybe = cell_rx.recv() => {
                let cell = match maybe {
                    Some(Ok(c)) => c,
                    Some(Err(TransportError::ConnectionClosed)) | None => break,
                    Some(Err(e)) => return Err(e),
                };
                match cell.cell_type {
                    CellType::Relay => {
                        let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                        let pt = ciphers.inbound.decrypt(&ct)?;
                        let inner = RelayCell::decode(&pt)?;

                        // Intercept Phase 2 circuit-extension commands before stream dispatch
                        match inner.command {
                            RelayCommand::Extend => {
                                if let Some(tx) = handle_extend(
                                    inner, circuit_id, ciphers, write_tx,
                                    relay2_inbound_tx.clone(),
                                ).await? {
                                    relay2_write_tx = Some(tx);
                                }
                                // if None: extend failed; error already sent to client
                            }
                            RelayCommand::Forward => {
                                // Client is forwarding inner ciphertext to relay2
                                if let Some(ref tx) = relay2_write_tx {
                                    let inner_ct_len = inner.data.len().min(RELAY_INNER_CT_LEN);
                                    let mut fwd_cell = Cell::new(circuit_id, CellType::RelayInner);
                                    fwd_cell.payload[..inner_ct_len]
                                        .copy_from_slice(&inner.data[..inner_ct_len]);
                                    if tx.send(fwd_cell.to_bytes()).await.is_err() {
                                        debug!("circuit {} relay2 write channel closed", circuit_id);
                                        relay2_write_tx = None;
                                    }
                                } else {
                                    warn!("circuit {} RELAY_FORWARD with no relay2 connection", circuit_id);
                                }
                            }
                            _ => {
                                dispatch_relay_cell(
                                    inner, circuit_id, ciphers, write_tx,
                                    Arc::clone(&streams), dest_tx.clone(),
                                    is_inner_hop,
                                ).await?;
                            }
                        }
                    }
                    CellType::RelayInner => {
                        // This relay is acting as relay2 (inner hop)
                        is_inner_hop = true;
                        let ct: &[u8; RELAY_INNER_CT_LEN] = cell.payload[..RELAY_INNER_CT_LEN]
                            .try_into()
                            .map_err(|_| TransportError::Protocol(
                                "RelayInner payload too short".into(),
                            ))?;
                        let pt = ciphers.inbound.decrypt_inner(ct)?;
                        let inner = RelayCell::decode_inner(&pt)?;
                        dispatch_relay_cell(
                            inner, circuit_id, ciphers, write_tx,
                            Arc::clone(&streams), dest_tx.clone(),
                            true, // inner-hop send mode
                        ).await?;
                    }
                    CellType::Destroy => {
                        debug!("circuit {} destroyed by client", circuit_id);
                        break;
                    }
                    CellType::Padding => {}
                    other => warn!("unexpected cell {:?} on circuit {}", other, circuit_id),
                }
            }

            // Inbound from relay2 (inner ciphertext) → wrap and forward to client
            Some(inner_ct) = relay2_inbound_rx.recv() => {
                send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
                    command: RelayCommand::Forward,
                    stream_id: 0,
                    data: inner_ct,
                }).await?;
            }

            // Outbound: data from destination → encrypt and send to client
            Some((stream_id, data)) = dest_rx.recv() => {
                if data.is_empty() {
                    // EOF from destination — send RELAY_END
                    streams.lock().await.remove(&stream_id);
                    send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop,
                        RelayCell { command: RelayCommand::End, stream_id, data: vec![] },
                    ).await?;
                } else {
                    // Chunk and send as RELAY_DATA cells
                    let max_chunk = if is_inner_hop {
                        use gptl_transport::cell::RELAY_INNER_MAX_DATA;
                        RELAY_INNER_MAX_DATA
                    } else {
                        RELAY_MAX_DATA
                    };
                    let mut remaining = data.as_slice();
                    while !remaining.is_empty() {
                        let n = remaining.len().min(max_chunk);
                        send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop, RelayCell {
                            command: RelayCommand::Data,
                            stream_id,
                            data: remaining[..n].to_vec(),
                        }).await?;
                        remaining = &remaining[n..];
                    }
                }
            }
        }
    }
    Ok(())
}

/// Route an already-decrypted relay cell to the appropriate stream handler.
async fn dispatch_relay_cell(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    is_inner_hop: bool,
) -> Result<(), TransportError> {
    match inner.command {
        RelayCommand::Begin => {
            begin_stream(inner, circuit_id, ciphers, write_tx, streams, dest_tx, is_inner_hop).await
        }
        RelayCommand::Data => {
            let mut map = streams.lock().await;
            if let Some(conn) = map.get_mut(&inner.stream_id) {
                if conn.write_half.write_all(&inner.data).await.is_err() {
                    let sid = inner.stream_id;
                    drop(map);
                    streams.lock().await.remove(&sid);
                    send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop,
                        RelayCell { command: RelayCommand::End, stream_id: sid, data: vec![] },
                    ).await?;
                }
            } else {
                debug!(
                    "circuit {} stream {} data for unknown stream, discarding {} bytes",
                    circuit_id, inner.stream_id, inner.data.len()
                );
            }
            Ok(())
        }
        RelayCommand::End => {
            streams.lock().await.remove(&inner.stream_id);
            Ok(())
        }
        other => {
            warn!(
                "circuit {} unhandled relay command {:?} on stream {}",
                circuit_id, other, inner.stream_id
            );
            Ok(())
        }
    }
}


async fn begin_stream(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    is_inner_hop: bool,
) -> Result<(), TransportError> {
    let stream_id = inner.stream_id;
    let target = String::from_utf8_lossy(&inner.data).to_string();

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
        None => (String::new(), None),
    };

    let port = match port {
        Some(p) if !host.is_empty() => p,
        _ => {
            return send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop, RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: b"invalid target".to_vec(),
            }).await;
        }
    };

    debug!("circuit {} stream {} → {}:{}", circuit_id, stream_id, host, port);

    let tcp = match TcpStream::connect((&*host, port)).await {
        Ok(s) => s,
        Err(e) => {
            debug!("stream {} connect failed: {}", stream_id, e);
            return send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop, RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: e.to_string().into_bytes(),
            }).await;
        }
    };

    // Send CONNECTED to client
    send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop, RelayCell {
        command: RelayCommand::Connected,
        stream_id,
        data: vec![],
    }).await?;

    // Split and store write half; spawn read task
    let (read_half, write_half) = tcp.into_split();
    streams.lock().await.insert(stream_id, OutboundConn { write_half });

    let tx = dest_tx.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut reader = read_half;
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    if tx.send((stream_id, vec![])).await.is_err() {
                        debug!("circuit stream {} dest_tx closed on EOF", stream_id);
                    }
                    break;
                }
                Ok(n) => {
                    if tx.send((stream_id, buf[..n].to_vec())).await.is_err() {
                        debug!("circuit stream {} dest_tx closed mid-stream", stream_id);
                        break;
                    }
                }
            }
        }
    });

    Ok(())
}

// ── Crypto send helpers ───────────────────────────────────────────────────────

/// Send an outer (single-hop exit) relay cell to the client.
async fn send_relay_cell(
    ciphers: &mut RelayCiphers,
    circuit_id: u32,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    inner: RelayCell,
) -> Result<(), TransportError> {
    use gptl_transport::cell::RELAY_PLAINTEXT_LEN;
    let pt: [u8; RELAY_PLAINTEXT_LEN] = inner.encode()?;
    let ct = ciphers.outbound.encrypt(&pt)?;
    let mut cell = Cell::new(circuit_id, CellType::Relay);
    cell.payload.copy_from_slice(&ct);
    write_tx.send(cell.to_bytes()).await.map_err(|_| TransportError::CircuitClosed)
}

/// Send an inner-hop (relay2) relay cell back to relay1.
async fn send_relay_cell_inner(
    ciphers: &mut RelayCiphers,
    circuit_id: u32,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    inner: RelayCell,
) -> Result<(), TransportError> {
    let pt: [u8; RELAY_INNER_PLAINTEXT_LEN] = inner.encode_inner()?;
    let ct = ciphers.outbound.encrypt_inner(&pt)?;
    let mut cell = Cell::new(circuit_id, CellType::RelayInner);
    cell.payload[..RELAY_INNER_CT_LEN].copy_from_slice(&ct);
    write_tx.send(cell.to_bytes()).await.map_err(|_| TransportError::CircuitClosed)
}

/// Send a relay cell using the appropriate mode (outer or inner hop).
async fn send_data_cell(
    ciphers: &mut RelayCiphers,
    circuit_id: u32,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    is_inner_hop: bool,
    inner: RelayCell,
) -> Result<(), TransportError> {
    if is_inner_hop {
        send_relay_cell_inner(ciphers, circuit_id, write_tx, inner).await
    } else {
        send_relay_cell(ciphers, circuit_id, write_tx, inner).await
    }
}

// ── Phase 2: RELAY_EXTEND handler ────────────────────────────────────────────

/// Send a RELAY_EXTEND_FAILED cell back to the client (non-fatal; circuit stays open).
async fn send_extend_failed(
    reason: &str,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
) -> Result<(), TransportError> {
    warn!("circuit {} RELAY_EXTEND failed: {}", circuit_id, reason);
    send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
        command: RelayCommand::ExtendFailed,
        stream_id: 0,
        data: reason.as_bytes().to_vec(),
    }).await
}

/// Handle a RELAY_EXTEND cell: connect to relay2, proxy CREATE/CREATED,
/// spawn forwarding tasks, and return a write channel to relay2.
///
/// Returns `Ok(Some(tx))` on success. On a non-fatal extend failure,
/// sends RELAY_EXTEND_FAILED to the client and returns `Ok(None)`.
/// A fatal I/O error (client write failed) returns `Err(...)`.
async fn handle_extend(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    relay2_inbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<Option<mpsc::Sender<[u8; CELL_SIZE]>>, TransportError> {
    // ── Parse RELAY_EXTEND payload ────────────────────────────────────────────
    // Layout (big-endian u32 lengths):
    //   [0..4]             addr_len
    //   [4..4+addr_len]    UTF-8 "ip:port"
    //   [off..off+32]      relay2 fingerprint (SHA-256 of static pubkey)
    //   [off+32..off+64]   client ephemeral X25519 pubkey (for relay2)
    //   [off+64..off+96]   client nonce (for relay2)
    let data = &inner.data;

    if data.len() < 4 {
        send_extend_failed("payload too short (< 4 bytes)", circuit_id, ciphers, write_tx).await?;
        return Ok(None);
    }
    let addr_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let required = 4usize.saturating_add(addr_len).saturating_add(96);
    if data.len() < required {
        send_extend_failed(
            &format!("payload truncated: need {} bytes, got {}", required, data.len()),
            circuit_id, ciphers, write_tx,
        ).await?;
        return Ok(None);
    }

    let addr = match std::str::from_utf8(&data[4..4 + addr_len]) {
        Ok(s) => s.to_string(),
        Err(_) => {
            send_extend_failed("non-UTF-8 address", circuit_id, ciphers, write_tx).await?;
            return Ok(None);
        }
    };

    let off = 4 + addr_len;
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&data[off..off + 32]);
    let mut client_eph = [0u8; 32];
    client_eph.copy_from_slice(&data[off + 32..off + 64]);
    let mut client_nonce_bytes = [0u8; 32];
    client_nonce_bytes.copy_from_slice(&data[off + 64..off + 96]);

    debug!(
        "circuit {} extending to {} (fp prefix {}...)",
        circuit_id, addr, hex::encode(&fp[..4])
    );

    // ── Connect to relay2 ─────────────────────────────────────────────────────
    let relay2_tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            send_extend_failed(
                &format!("connect to {}: {}", addr, e),
                circuit_id, ciphers, write_tx,
            ).await?;
            return Ok(None);
        }
    };
    let _ = relay2_tcp.set_nodelay(true);
    let mut relay2_conn = RelayConn::new(relay2_tcp);

    // ── Build and send CREATE cell (forwarding client's key material) ─────────
    let mut create = Cell::new(circuit_id, CellType::Create);
    create.payload[0..32].copy_from_slice(&fp);
    create.payload[32..64].copy_from_slice(&client_eph);
    create.payload[64..96].copy_from_slice(&client_nonce_bytes);

    if let Err(e) = relay2_conn.send(&create).await {
        send_extend_failed(
            &format!("send CREATE to relay2: {}", e),
            circuit_id, ciphers, write_tx,
        ).await?;
        return Ok(None);
    }

    // ── Read CREATED from relay2 ──────────────────────────────────────────────
    let created = match relay2_conn.recv().await {
        Ok(c) => c,
        Err(e) => {
            send_extend_failed(
                &format!("recv CREATED from relay2: {}", e),
                circuit_id, ciphers, write_tx,
            ).await?;
            return Ok(None);
        }
    };
    if !matches!(created.cell_type, CellType::Created) {
        send_extend_failed(
            &format!("relay2 sent {:?} (expected CREATED)", created.cell_type),
            circuit_id, ciphers, write_tx,
        ).await?;
        return Ok(None);
    }

    // ── Forward CREATED payload as RELAY_EXTENDED to client ──────────────────
    // The first 96 bytes are: relay2_eph_pub(32) || relay2_nonce(32) || confirmation(32)
    let extended_data = created.payload[0..96].to_vec();
    send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
        command: RelayCommand::Extended,
        stream_id: 0,
        data: extended_data,
    }).await?;

    debug!("circuit {} extended successfully to {}", circuit_id, addr);

    // ── Spawn relay2 I/O tasks ────────────────────────────────────────────────
    let relay2_stream = relay2_conn.into_inner();
    let (relay2_read_half, mut relay2_write_half) = relay2_stream.into_split();

    // Writer: main loop → relay2
    let (relay2_cell_tx, mut relay2_cell_rx) = mpsc::channel::<[u8; CELL_SIZE]>(64);
    tokio::spawn(async move {
        while let Some(bytes) = relay2_cell_rx.recv().await {
            if relay2_write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // Reader: relay2 → main loop (extract inner ciphertext from RelayInner cells)
    tokio::spawn(async move {
        let mut rdr = relay2_read_half;
        let mut buf = [0u8; CELL_SIZE];
        loop {
            match rdr.read_exact(&mut buf).await {
                Ok(_) if buf[4] == CellType::RelayInner as u8 => {
                    // Payload offset 0..RELAY_INNER_CT_LEN holds the inner ciphertext
                    let inner_ct = buf[5..5 + RELAY_INNER_CT_LEN].to_vec();
                    if relay2_inbound_tx.send(inner_ct).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {} // padding and other cells from relay2 are silently dropped
                Err(_) => break,
            }
        }
    });

    Ok(Some(relay2_cell_tx))
}

// ── Argument parsing ──────────────────────────────────────────────────────────

struct Args {
    key_path: Option<PathBuf>,
    listen: SocketAddr,
    nickname: String,
    print_descriptor: bool,
    log_level: String,
}

fn parse_args() -> Args {
    let mut key_path: Option<PathBuf> = None;
    let mut listen: SocketAddr = "0.0.0.0:9001".parse().unwrap();
    let mut nickname = hostname_or_default();
    let mut print_descriptor = false;
    let mut log_level = "info".to_string();

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--key"  => { key_path = Some(PathBuf::from(next_arg(&arg, &mut iter))); }
            "--listen" => {
                let val = next_arg(&arg, &mut iter);
                listen = val.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid listen address '{}'", val);
                    std::process::exit(1);
                });
            }
            "--nickname" => { nickname = next_arg(&arg, &mut iter); }
            "--print-descriptor" => { print_descriptor = true; }
            "--log" => { log_level = next_arg(&arg, &mut iter); }
            "--help" | "-h" => { print_usage(); std::process::exit(0); }
            unknown => {
                eprintln!("error: unknown argument '{}'", unknown);
                std::process::exit(1);
            }
        }
    }

    Args { key_path, listen, nickname, print_descriptor, log_level }
}

fn next_arg(flag: &str, iter: &mut impl Iterator<Item = String>) -> String {
    iter.next().unwrap_or_else(|| {
        eprintln!("error: '{}' requires a value", flag);
        std::process::exit(1);
    })
}

fn print_usage() {
    println!("gptl-node — GPTL relay node");
    println!();
    println!("USAGE:");
    println!("  gptl-node [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --key <PATH>             Path to 32-byte hex private key file");
    println!("  --listen <ADDR>          Listen address (default: 0.0.0.0:9001)");
    println!("  --nickname <NAME>        Relay display name");
    println!("  --print-descriptor       Print JSON descriptor and exit");
    println!("  --log <LEVEL>            Log level (default: info)");
    println!("  -h, --help               Print this help");
    println!();
    println!("EXAMPLE:");
    println!("  gptl-node --key /etc/gptl/relay.key --print-descriptor");
}

// ── Key management ────────────────────────────────────────────────────────────

fn load_or_generate_key(path: Option<&std::path::Path>) -> RelayStaticKey {
    if let Some(p) = path {
        if p.exists() {
            let hex = std::fs::read_to_string(p).unwrap_or_else(|e| {
                eprintln!("error reading key {}: {}", p.display(), e);
                std::process::exit(1);
            });
            let bytes = hex::decode(hex.trim()).unwrap_or_else(|e| {
                eprintln!("error decoding key hex: {}", e);
                std::process::exit(1);
            });
            if bytes.len() != 32 {
                eprintln!("error: key file must be 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return RelayStaticKey::from_bytes(arr);
        }
    }
    let key = RelayStaticKey::generate();
    eprintln!("generated new relay key; use --key <PATH> to persist it");
    key
}

fn persist_key(key: &RelayStaticKey, path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let hex = hex::encode(*key.private);
    std::fs::write(path, &hex).unwrap_or_else(|e| {
        warn!("could not save key to {}: {}", path.display(), e);
    });
    info!("saved new key to {}", path.display());
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn hostname_or_default() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "gptl-relay".to_string())
}

/// Best-effort public IP detection via UDP connect trick.
fn public_ip_hint() -> String {
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = s.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "0.0.0.0".to_string()
}

fn init_logging(level: &str) {
    use std::str::FromStr;
    let filter = tracing_subscriber::filter::LevelFilter::from_str(level)
        .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();
}
