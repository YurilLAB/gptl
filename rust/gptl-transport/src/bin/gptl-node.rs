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
    cell::{Cell, CellType, RelayCell, RelayCommand, CELL_PAYLOAD_LEN, CELL_SIZE, RELAY_MAX_DATA},
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
    loop {
        tokio::select! {
            // Inbound: cell from client
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
                        dispatch_relay_cell(
                            inner, circuit_id, ciphers, write_tx,
                            Arc::clone(&streams), dest_tx.clone(),
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

            // Outbound: data from destination → encrypt and send to client
            Some((stream_id, data)) = dest_rx.recv() => {
                if data.is_empty() {
                    // EOF from destination — send RELAY_END
                    streams.lock().await.remove(&stream_id);
                    send_relay_cell(ciphers, circuit_id, write_tx,
                        RelayCell { command: RelayCommand::End, stream_id, data: vec![] },
                    ).await?;
                } else {
                    // Chunk and send as RELAY_DATA cells
                    let mut remaining = data.as_slice();
                    while !remaining.is_empty() {
                        let n = remaining.len().min(RELAY_MAX_DATA);
                        send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
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

async fn dispatch_relay_cell(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
) -> Result<(), TransportError> {
    match inner.command {
        RelayCommand::Begin => {
            begin_stream(inner, circuit_id, ciphers, write_tx, streams, dest_tx).await
        }
        RelayCommand::Data => {
            let mut map = streams.lock().await;
            if let Some(conn) = map.get_mut(&inner.stream_id) {
                if conn.write_half.write_all(&inner.data).await.is_err() {
                    let sid = inner.stream_id;
                    drop(map);
                    streams.lock().await.remove(&sid);
                    send_relay_cell(ciphers, circuit_id, write_tx,
                        RelayCell { command: RelayCommand::End, stream_id: sid, data: vec![] },
                    ).await?;
                }
            }
            Ok(())
        }
        RelayCommand::End => {
            streams.lock().await.remove(&inner.stream_id);
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn begin_stream(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
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
            return send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
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
            return send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: e.to_string().into_bytes(),
            }).await;
        }
    };

    // Send CONNECTED to client
    send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
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
                Ok(0) | Err(_) => { let _ = tx.send((stream_id, vec![])).await; break; }
                Ok(n) => { if tx.send((stream_id, buf[..n].to_vec())).await.is_err() { break; } }
            }
        }
    });

    Ok(())
}

// ── Crypto send helper ────────────────────────────────────────────────────────

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
