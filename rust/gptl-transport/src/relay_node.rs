//! Relay-node runtime — the cell-protocol logic that powers `gptl-node`
//! and (with security gates layered in front) the `secure-relay` binary
//! in `gptl-relay`.
//!
//! This module owns:
//!   * the per-client accept loop ([`RelayNode::run`])
//!   * the per-connection handler ([`RelayNode::handle_connection`])
//!   * the circuit driver (CREATE handshake → cell-level select loop)
//!   * stream multiplexing and the relay-side exit policy
//!
//! Previously all of this lived in `bin/gptl-node.rs`, so reusing it
//! from a different binary (e.g. `secure-relay`) was impossible.

use crate::{
    cell::{
        Cell, CellType, RelayCell, RelayCommand, CELL_PAYLOAD_LEN, CELL_SIZE, RELAY_INNER_CT_LEN,
        RELAY_INNER_MAX_DATA, RELAY_INNER_PLAINTEXT_LEN, RELAY_MAX_DATA, RELAY_PLAINTEXT_LEN,
    },
    crypto::RelayCiphers,
    handshake::{relay_respond, RelayStaticKey},
    metrics::RelayMetrics,
    relay_conn::RelayConn,
    TransportError,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

// ── Public configuration ────────────────────────────────────────────────────

/// Tunables for a [`RelayNode`].  All fields have sensible production
/// defaults; for tests / local-network setups, override individual
/// fields with the builder methods.
#[derive(Debug, Clone)]
pub struct RelayOptions {
    /// Maximum concurrent circuits before the accept loop starts
    /// rejecting connections.  Default: 1000.
    pub max_circuits: usize,
    /// Maximum concurrent streams within a single circuit.  Default: 256.
    pub max_streams_per_circuit: u16,
    /// How long to wait for the initial CREATE cell after TCP accept.
    /// Default: 30 s.
    pub handshake_timeout: Duration,
    /// Hard cap on a single circuit's lifetime.  Default: 3600 s (1 h).
    pub max_circuit_lifetime: Duration,
    /// When `true`, the relay's exit policy permits loopback / RFC1918
    /// destinations.  For local testing only — do NOT enable in
    /// production; doing so turns the relay into an open LAN proxy.
    pub allow_private: bool,
    /// Destination ports the relay refuses to exit to (typical: SMTP).
    pub blocked_ports: Vec<u16>,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            max_circuits: 1000,
            max_streams_per_circuit: 256,
            handshake_timeout: Duration::from_secs(30),
            max_circuit_lifetime: Duration::from_secs(3600),
            allow_private: false,
            // SMTP submission ports — a common open-relay abuse vector.
            blocked_ports: vec![25, 587, 465],
        }
    }
}

impl RelayOptions {
    /// Convenience: enable `allow_private` (testing only).
    pub fn with_allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }
    /// Override the per-instance circuit cap.
    pub fn with_max_circuits(mut self, n: usize) -> Self {
        self.max_circuits = n;
        self
    }
}

/// The relay's identity + operational state.  Cheaply cloneable via
/// `Arc<RelayNode>`; share one instance across all incoming connections.
pub struct RelayNode {
    static_key: Arc<RelayStaticKey>,
    active_circuits: Arc<AtomicUsize>,
    options: RelayOptions,
    metrics: Arc<RelayMetrics>,
}

impl std::fmt::Debug for RelayNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayNode")
            .field("fingerprint", &hex::encode(self.static_key.fingerprint))
            .field(
                "active_circuits",
                &self.active_circuits.load(Ordering::Relaxed),
            )
            .field("max_circuits", &self.options.max_circuits)
            .field("allow_private", &self.options.allow_private)
            .finish()
    }
}

impl RelayNode {
    /// Build a new relay node from a static key and options.  Uses a
    /// fresh default-zero metrics struct.  Call [`with_metrics`] to
    /// share counters with an external `/metrics` HTTP endpoint.
    pub fn new(static_key: RelayStaticKey, options: RelayOptions) -> Self {
        Self {
            static_key: Arc::new(static_key),
            active_circuits: Arc::new(AtomicUsize::new(0)),
            options,
            metrics: RelayMetrics::new(),
        }
    }

    /// Replace the internal metrics object so a Prometheus endpoint
    /// can read counters without holding a reference to the node.
    pub fn with_metrics(mut self, metrics: Arc<RelayMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Borrow the metrics object for use by an external HTTP exposer.
    pub fn metrics(&self) -> Arc<RelayMetrics> {
        Arc::clone(&self.metrics)
    }

    /// SHA-256 of the static public key — what clients use as a
    /// long-term relay identifier in their bootstrap directory.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.static_key.fingerprint
    }

    /// The static X25519 public key for this relay.  Clients hash this
    /// into their handshake to verify they're talking to the right relay.
    pub fn public_key(&self) -> [u8; 32] {
        self.static_key.public
    }

    /// Number of circuits currently being served.
    pub fn active_circuit_count(&self) -> usize {
        self.active_circuits.load(Ordering::Relaxed)
    }

    /// Read-only view of the configured options.
    pub fn options(&self) -> &RelayOptions {
        &self.options
    }

    /// Run the accept loop on `listener` forever.  Each accepted
    /// connection is spawned on its own task and counted against the
    /// `max_circuits` cap.
    ///
    /// Returns only on a fatal error (a successful accept loop never
    /// terminates).  Transient accept errors are logged at error level
    /// and the loop continues.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<(), TransportError> {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!("accept: {}", e);
                    continue;
                }
            };

            self.metrics
                .connections_total
                .fetch_add(1, Ordering::Relaxed);

            if self.active_circuits.load(Ordering::Relaxed) >= self.options.max_circuits {
                warn!(
                    "circuit limit reached ({}), rejecting {}",
                    self.options.max_circuits, peer
                );
                self.metrics
                    .circuits_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }

            debug!("connection from {}", peer);

            let node = Arc::clone(&self);
            tokio::spawn(async move {
                let n = node.active_circuits.fetch_add(1, Ordering::Relaxed) + 1;
                node.metrics
                    .active_circuits
                    .store(n as u64, Ordering::Relaxed);
                if let Err(e) = node.handle_connection(stream, peer).await {
                    match e {
                        TransportError::ConnectionClosed | TransportError::CircuitClosed => {}
                        other => warn!("client {} ended: {}", peer, other),
                    }
                }
                let n = node
                    .active_circuits
                    .fetch_sub(1, Ordering::Relaxed)
                    .saturating_sub(1);
                node.metrics
                    .active_circuits
                    .store(n as u64, Ordering::Relaxed);
            });
        }
    }

    /// Handle a single already-accepted TCP stream.
    ///
    /// This is the entry point [`secure-relay`](../../../gptl-relay) uses
    /// after its IP-allowlist / rate-limit checks pass.  The caller is
    /// responsible for any pre-handshake gating; this function performs
    /// the ntor-lite handshake and then drives the circuit until it
    /// closes or hits `options.max_circuit_lifetime`.
    pub async fn handle_connection(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), TransportError> {
        let _ = stream.set_nodelay(true);
        let mut conn = RelayConn::new(stream);

        // Wait for the CREATE cell with a bounded timeout so a quiet
        // attacker can't tie up a circuit slot indefinitely.
        let create = match tokio::time::timeout(self.options.handshake_timeout, conn.recv()).await {
            Ok(Ok(cell)) => cell,
            Ok(Err(e)) => {
                self.metrics
                    .handshakes_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
            Err(_) => {
                self.metrics
                    .handshakes_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(TransportError::Protocol(format!(
                    "handshake timeout: no CREATE cell within {}s",
                    self.options.handshake_timeout.as_secs()
                )));
            }
        };
        if !matches!(create.cell_type, CellType::Create) {
            self.metrics
                .handshakes_failed_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(TransportError::Protocol(format!(
                "expected CREATE, got {:?}",
                create.cell_type
            )));
        }

        let circuit_id = create.circuit_id;
        let (created, keys) = match relay_respond(&create, &self.static_key) {
            Ok(v) => v,
            Err(e) => {
                self.metrics
                    .handshakes_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        conn.send(&created).await?;
        self.metrics
            .handshakes_total
            .fetch_add(1, Ordering::Relaxed);
        debug!("circuit {} established with {}", circuit_id, peer);

        let ciphers = RelayCiphers::new(&keys.forward_key, &keys.backward_key);
        relay_circuit(conn, circuit_id, ciphers, &self.options, &self.metrics).await
    }
}

// ── Internal: per-circuit driver ─────────────────────────────────────────────

/// Destination write-half plus per-stream metadata.
struct OutboundConn {
    write_half: tokio::net::tcp::OwnedWriteHalf,
}

async fn relay_circuit(
    conn: RelayConn,
    circuit_id: u32,
    mut ciphers: RelayCiphers,
    options: &RelayOptions,
    metrics: &Arc<RelayMetrics>,
) -> Result<(), TransportError> {
    let tcp = conn.into_inner();
    let (mut read_half, write_half) = tcp.into_split();

    let (cell_tx, mut cell_rx) = mpsc::channel::<Result<Cell, TransportError>>(64);
    let (write_tx, mut write_rx) = mpsc::channel::<[u8; CELL_SIZE]>(256);
    let (dest_tx, mut dest_rx) = mpsc::channel::<(u16, Vec<u8>)>(256);

    // Reader task: raw cells off the wire.
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

    // Writer task: raw cells onto the wire.
    let mut write_half = write_half;
    tokio::spawn(async move {
        while let Some(bytes) = write_rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    });

    let streams: Arc<Mutex<HashMap<u16, OutboundConn>>> = Arc::new(Mutex::new(HashMap::new()));

    let result = match tokio::time::timeout(
        options.max_circuit_lifetime,
        run_relay_loop(
            circuit_id,
            &mut ciphers,
            &mut cell_rx,
            &write_tx,
            &mut dest_rx,
            dest_tx,
            Arc::clone(&streams),
            options,
            metrics,
        ),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            info!(
                "circuit {} reached maximum lifetime ({}s), tearing down",
                circuit_id,
                options.max_circuit_lifetime.as_secs()
            );
            Ok(())
        }
    };

    streams.lock().await.clear();
    let destroy = Cell::new(circuit_id, CellType::Destroy);
    let _ = write_tx.send(destroy.to_bytes()).await;

    result
}

#[allow(clippy::too_many_arguments)]
async fn run_relay_loop(
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    cell_rx: &mut mpsc::Receiver<Result<Cell, TransportError>>,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    dest_rx: &mut mpsc::Receiver<(u16, Vec<u8>)>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    options: &RelayOptions,
    metrics: &Arc<RelayMetrics>,
) -> Result<(), TransportError> {
    let (relay2_inbound_tx, mut relay2_inbound_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut relay2_write_tx: Option<mpsc::Sender<[u8; CELL_SIZE]>> = None;
    let mut is_inner_hop = false;

    loop {
        tokio::select! {
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

                        match inner.command {
                            RelayCommand::Extend => {
                                match handle_extend(
                                    inner, circuit_id, ciphers, write_tx,
                                    relay2_inbound_tx.clone(),
                                ).await? {
                                    Some(tx) => {
                                        relay2_write_tx = Some(tx);
                                        metrics
                                            .extends_total
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    None => {
                                        metrics
                                            .extends_failed_total
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            RelayCommand::Forward => {
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
                                    warn!(
                                        "circuit {} RELAY_FORWARD with no relay2 connection",
                                        circuit_id
                                    );
                                }
                            }
                            _ => {
                                dispatch_relay_cell(
                                    inner, circuit_id, ciphers, write_tx,
                                    Arc::clone(&streams), dest_tx.clone(),
                                    is_inner_hop, options, metrics,
                                ).await?;
                            }
                        }
                    }
                    CellType::RelayInner => {
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
                            true, options, metrics,
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

            Some(inner_ct) = relay2_inbound_rx.recv() => {
                send_relay_cell(ciphers, circuit_id, write_tx, RelayCell {
                    command: RelayCommand::Forward,
                    stream_id: 0,
                    data: inner_ct,
                }).await?;
            }

            Some((stream_id, data)) = dest_rx.recv() => {
                if data.is_empty() {
                    streams.lock().await.remove(&stream_id);
                    send_data_cell(ciphers, circuit_id, write_tx, is_inner_hop,
                        RelayCell { command: RelayCommand::End, stream_id, data: vec![] },
                    ).await?;
                } else {
                    let max_chunk = if is_inner_hop {
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

#[allow(clippy::too_many_arguments)]
async fn dispatch_relay_cell(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    is_inner_hop: bool,
    options: &RelayOptions,
    metrics: &Arc<RelayMetrics>,
) -> Result<(), TransportError> {
    match inner.command {
        RelayCommand::Begin => {
            begin_stream(
                inner,
                circuit_id,
                ciphers,
                write_tx,
                streams,
                dest_tx,
                is_inner_hop,
                options,
                metrics,
            )
            .await
        }
        RelayCommand::Data => {
            let mut map = streams.lock().await;
            if let Some(conn) = map.get_mut(&inner.stream_id) {
                if conn.write_half.write_all(&inner.data).await.is_err() {
                    let sid = inner.stream_id;
                    drop(map);
                    streams.lock().await.remove(&sid);
                    send_data_cell(
                        ciphers,
                        circuit_id,
                        write_tx,
                        is_inner_hop,
                        RelayCell {
                            command: RelayCommand::End,
                            stream_id: sid,
                            data: vec![],
                        },
                    )
                    .await?;
                }
            } else {
                debug!(
                    "circuit {} stream {} data for unknown stream, discarding {} bytes",
                    circuit_id,
                    inner.stream_id,
                    inner.data.len(),
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

/// Exit policy for a concrete IP address: `true` for any address that must not
/// be reachable through the relay (loopback, RFC1918, CGNAT, link-local,
/// multicast, documentation, unspecified/broadcast, IPv6 ULA/link-local, and
/// IPv4-mapped forms of all of the above).
pub fn is_private_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};

    fn v4_blocked(v4: Ipv4Addr) -> bool {
        let o = v4.octets();
        v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_unspecified()
            || v4.is_broadcast()
            || v4.is_documentation()
            || v4.is_multicast()
            // 100.64.0.0/10 — carrier-grade NAT (RFC 6598)
            || (o[0] == 100 && (o[1] & 0xc0) == 64)
    }

    match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped addresses (::ffff:a.b.c.d) must be checked as IPv4 so a
            // request to ::ffff:127.0.0.1 cannot bypass the v4 rules. Use
            // to_ipv4_mapped (not to_ipv4) so genuine v6 addresses like ::1 are
            // not mis-mapped and instead fall through to the v6 checks below.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_blocked(v4);
            }
            let seg0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Exit policy for a target string: `true` for a private/reserved literal IP or
/// a hostname that names a local resource (`localhost` / `.local` /
/// `.internal`).
///
/// NOTE: a `false` result for a hostname does NOT mean the connection is safe —
/// the name may still resolve to a private address. Callers must resolve the
/// host and re-check every candidate IP with [`is_private_ip`] before
/// connecting (see `begin_stream`).
pub fn is_private_address(host: &str) -> bool {
    let cleaned = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = cleaned.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }
    let lower = host.to_lowercase();
    lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal")
}

#[allow(clippy::too_many_arguments)]
async fn begin_stream(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    streams: Arc<Mutex<HashMap<u16, OutboundConn>>>,
    dest_tx: mpsc::Sender<(u16, Vec<u8>)>,
    is_inner_hop: bool,
    options: &RelayOptions,
    metrics: &Arc<RelayMetrics>,
) -> Result<(), TransportError> {
    let stream_id = inner.stream_id;

    {
        let map = streams.lock().await;
        if map.len() >= options.max_streams_per_circuit as usize {
            metrics
                .streams_blocked_total
                .fetch_add(1, Ordering::Relaxed);
            return send_data_cell(
                ciphers,
                circuit_id,
                write_tx,
                is_inner_hop,
                RelayCell {
                    command: RelayCommand::BeginFailed,
                    stream_id,
                    data: b"max streams exceeded".to_vec(),
                },
            )
            .await;
        }
    }

    let target = String::from_utf8_lossy(&inner.data).to_string();

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
        None => (String::new(), None),
    };

    let port = match port {
        Some(p) if !host.is_empty() => p,
        _ => {
            return send_data_cell(
                ciphers,
                circuit_id,
                write_tx,
                is_inner_hop,
                RelayCell {
                    command: RelayCommand::BeginFailed,
                    stream_id,
                    data: b"invalid target".to_vec(),
                },
            )
            .await;
        }
    };

    if is_private_address(&host) && !options.allow_private {
        warn!(
            "circuit {} stream {} blocked: private address {}",
            circuit_id, stream_id, host
        );
        metrics
            .streams_blocked_total
            .fetch_add(1, Ordering::Relaxed);
        return send_data_cell(
            ciphers,
            circuit_id,
            write_tx,
            is_inner_hop,
            RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: b"exit policy: private address blocked".to_vec(),
            },
        )
        .await;
    }

    if options.blocked_ports.contains(&port) {
        warn!(
            "circuit {} stream {} blocked: port {}",
            circuit_id, stream_id, port
        );
        metrics
            .streams_blocked_total
            .fetch_add(1, Ordering::Relaxed);
        return send_data_cell(
            ciphers,
            circuit_id,
            write_tx,
            is_inner_hop,
            RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: b"exit policy: port blocked".to_vec(),
            },
        )
        .await;
    }

    debug!(
        "circuit {} stream {} → {}:{}",
        circuit_id, stream_id, host, port
    );

    // Resolve the host and validate EVERY candidate IP before connecting. The
    // literal is_private_address() check above is necessary but not sufficient:
    // a hostname can resolve (at connect time) to a private/reserved address —
    // a DNS-rebinding SSRF that could reach loopback, RFC1918 hosts, or the
    // cloud metadata endpoint (169.254.169.254). We resolve once and connect
    // only to the vetted IPs, so no second (rebindable) resolution happens.
    let resolved: Vec<std::net::SocketAddr> =
        match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                debug!("stream {} resolve failed: {}", stream_id, e);
                return send_data_cell(
                    ciphers,
                    circuit_id,
                    write_tx,
                    is_inner_hop,
                    RelayCell {
                        command: RelayCommand::BeginFailed,
                        stream_id,
                        data: e.to_string().into_bytes(),
                    },
                )
                .await;
            }
        };

    let allowed: Vec<std::net::SocketAddr> = if options.allow_private {
        resolved
    } else {
        resolved
            .into_iter()
            .filter(|sa| !is_private_ip(sa.ip()))
            .collect()
    };

    if allowed.is_empty() {
        warn!(
            "circuit {} stream {} blocked: {} resolved only to private/reserved addresses",
            circuit_id, stream_id, host
        );
        metrics
            .streams_blocked_total
            .fetch_add(1, Ordering::Relaxed);
        return send_data_cell(
            ciphers,
            circuit_id,
            write_tx,
            is_inner_hop,
            RelayCell {
                command: RelayCommand::BeginFailed,
                stream_id,
                data: b"exit policy: private address blocked".to_vec(),
            },
        )
        .await;
    }

    let tcp = match TcpStream::connect(&allowed[..]).await {
        Ok(s) => s,
        Err(e) => {
            debug!("stream {} connect failed: {}", stream_id, e);
            return send_data_cell(
                ciphers,
                circuit_id,
                write_tx,
                is_inner_hop,
                RelayCell {
                    command: RelayCommand::BeginFailed,
                    stream_id,
                    data: e.to_string().into_bytes(),
                },
            )
            .await;
        }
    };

    send_data_cell(
        ciphers,
        circuit_id,
        write_tx,
        is_inner_hop,
        RelayCell {
            command: RelayCommand::Connected,
            stream_id,
            data: vec![],
        },
    )
    .await?;
    metrics.streams_opened_total.fetch_add(1, Ordering::Relaxed);

    let (read_half, write_half) = tcp.into_split();
    streams
        .lock()
        .await
        .insert(stream_id, OutboundConn { write_half });

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

// ── Cell-send helpers ──────────────────────────────────────────────────────

async fn send_relay_cell(
    ciphers: &mut RelayCiphers,
    circuit_id: u32,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    inner: RelayCell,
) -> Result<(), TransportError> {
    let pt: [u8; RELAY_PLAINTEXT_LEN] = inner.encode()?;
    let ct = ciphers.outbound.encrypt(&pt)?;
    let mut cell = Cell::new(circuit_id, CellType::Relay);
    cell.payload.copy_from_slice(&ct);
    write_tx
        .send(cell.to_bytes())
        .await
        .map_err(|_| TransportError::CircuitClosed)
}

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
    write_tx
        .send(cell.to_bytes())
        .await
        .map_err(|_| TransportError::CircuitClosed)
}

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

async fn send_extend_failed(
    reason: &str,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
) -> Result<(), TransportError> {
    warn!("circuit {} RELAY_EXTEND failed: {}", circuit_id, reason);
    send_relay_cell(
        ciphers,
        circuit_id,
        write_tx,
        RelayCell {
            command: RelayCommand::ExtendFailed,
            stream_id: 0,
            data: reason.as_bytes().to_vec(),
        },
    )
    .await
}

// ── Phase 2: RELAY_EXTEND handler ─────────────────────────────────────────

async fn handle_extend(
    inner: RelayCell,
    circuit_id: u32,
    ciphers: &mut RelayCiphers,
    write_tx: &mpsc::Sender<[u8; CELL_SIZE]>,
    relay2_inbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<Option<mpsc::Sender<[u8; CELL_SIZE]>>, TransportError> {
    let data = &inner.data;

    if data.len() < 4 {
        send_extend_failed(
            "payload too short (< 4 bytes)",
            circuit_id,
            ciphers,
            write_tx,
        )
        .await?;
        return Ok(None);
    }
    let addr_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let required = 4usize.saturating_add(addr_len).saturating_add(96);
    if data.len() < required {
        send_extend_failed(
            &format!(
                "payload truncated: need {} bytes, got {}",
                required,
                data.len()
            ),
            circuit_id,
            ciphers,
            write_tx,
        )
        .await?;
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
        circuit_id,
        addr,
        hex::encode(&fp[..4])
    );

    let relay2_tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            send_extend_failed(
                &format!("connect to {}: {}", addr, e),
                circuit_id,
                ciphers,
                write_tx,
            )
            .await?;
            return Ok(None);
        }
    };
    let _ = relay2_tcp.set_nodelay(true);
    let mut relay2_conn = RelayConn::new(relay2_tcp);

    let mut create = Cell::new(circuit_id, CellType::Create);
    create.payload[0..32].copy_from_slice(&fp);
    create.payload[32..64].copy_from_slice(&client_eph);
    create.payload[64..96].copy_from_slice(&client_nonce_bytes);

    if let Err(e) = relay2_conn.send(&create).await {
        send_extend_failed(
            &format!("send CREATE to relay2: {}", e),
            circuit_id,
            ciphers,
            write_tx,
        )
        .await?;
        return Ok(None);
    }

    let created = match relay2_conn.recv().await {
        Ok(c) => c,
        Err(e) => {
            send_extend_failed(
                &format!("recv CREATED from relay2: {}", e),
                circuit_id,
                ciphers,
                write_tx,
            )
            .await?;
            return Ok(None);
        }
    };
    if !matches!(created.cell_type, CellType::Created) {
        send_extend_failed(
            &format!("relay2 sent {:?} (expected CREATED)", created.cell_type),
            circuit_id,
            ciphers,
            write_tx,
        )
        .await?;
        return Ok(None);
    }

    let extended_data = created.payload[0..96].to_vec();
    send_relay_cell(
        ciphers,
        circuit_id,
        write_tx,
        RelayCell {
            command: RelayCommand::Extended,
            stream_id: 0,
            data: extended_data,
        },
    )
    .await?;

    debug!("circuit {} extended successfully to {}", circuit_id, addr);

    let relay2_stream = relay2_conn.into_inner();
    let (relay2_read_half, mut relay2_write_half) = relay2_stream.into_split();

    let (relay2_cell_tx, mut relay2_cell_rx) = mpsc::channel::<[u8; CELL_SIZE]>(64);
    tokio::spawn(async move {
        while let Some(bytes) = relay2_cell_rx.recv().await {
            if relay2_write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut rdr = relay2_read_half;
        let mut buf = [0u8; CELL_SIZE];
        loop {
            match rdr.read_exact(&mut buf).await {
                Ok(_) if buf[4] == CellType::RelayInner as u8 => {
                    let inner_ct = buf[5..5 + RELAY_INNER_CT_LEN].to_vec();
                    if relay2_inbound_tx.send(inner_ct).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    Ok(Some(relay2_cell_tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_address_blocks_loopback_and_rfc1918() {
        assert!(is_private_address("127.0.0.1"));
        assert!(is_private_address("10.0.0.1"));
        assert!(is_private_address("192.168.1.1"));
        assert!(is_private_address("172.16.0.1"));
        assert!(is_private_address("localhost"));
        assert!(is_private_address("foo.local"));
        assert!(is_private_address("foo.internal"));
        assert!(is_private_address("[::1]"));
        assert!(is_private_address("169.254.1.1"));
    }

    #[test]
    fn test_is_private_address_allows_public() {
        assert!(!is_private_address("8.8.8.8"));
        assert!(!is_private_address("1.1.1.1"));
        assert!(!is_private_address("example.com"));
        assert!(!is_private_address("[2606:4700:4700::1111]"));
    }

    #[test]
    fn test_is_private_ip_blocks_reserved_ranges() {
        use std::net::IpAddr;
        let blocked = [
            "127.0.0.1",        // loopback
            "169.254.169.254",  // cloud metadata (link-local)
            "100.64.0.1",       // CGNAT (RFC 6598)
            "::1",              // IPv6 loopback
            "::ffff:127.0.0.1", // IPv4-mapped loopback (bypass attempt)
            "::ffff:10.0.0.1",  // IPv4-mapped RFC1918
            "fc00::1",          // IPv6 unique-local
            "fe80::1",          // IPv6 link-local
            "224.0.0.1",        // multicast
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_private_ip(ip), "{} must be blocked", s);
        }

        let allowed = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_private_ip(ip), "{} must be allowed", s);
        }
    }

    #[test]
    fn test_default_options_have_reasonable_caps() {
        let o = RelayOptions::default();
        assert_eq!(o.max_circuits, 1000);
        assert_eq!(o.max_streams_per_circuit, 256);
        assert!(!o.allow_private, "default must NOT permit private targets");
        assert!(
            o.blocked_ports.contains(&25),
            "SMTP must be blocked by default to discourage open-relay abuse"
        );
    }

    #[test]
    fn test_relay_node_exposes_identity() {
        let key = RelayStaticKey::generate();
        let fp = key.fingerprint;
        let pk = key.public;
        let node = RelayNode::new(key, RelayOptions::default());
        assert_eq!(node.fingerprint(), fp);
        assert_eq!(node.public_key(), pk);
        assert_eq!(node.active_circuit_count(), 0);
    }

    #[tokio::test]
    async fn test_relay_node_handles_one_full_circuit_with_loopback_exit() {
        use crate::cell::{Cell, CellType, RelayCommand, RELAY_MAX_DATA};
        use crate::handshake::client_finish;
        use crate::handshake::client_initiate;
        use std::io::{Read, Write};

        // Spawn a local echo server that the relay will exit to.
        let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in echo.incoming() {
                if let Ok(mut s) = s {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });

        // Spin up the relay node bound to a random port with allow_private.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = listener.local_addr().unwrap();
        let key = RelayStaticKey::generate();
        let static_pub = key.public;
        let node = Arc::new(RelayNode::new(
            key,
            RelayOptions::default().with_allow_private(true),
        ));
        let node_for_run = Arc::clone(&node);
        tokio::spawn(async move {
            let _ = node_for_run.run(listener).await;
        });

        // Build a 1-hop circuit by hand.
        let mut conn = RelayConn::connect(relay_addr).await.unwrap();
        let circuit_id = 0x1234_5678u32 | 1;
        let (create, pending) = client_initiate(circuit_id, &static_pub).unwrap();
        conn.send(&create).await.unwrap();
        let created = conn.recv().await.unwrap();
        let session = client_finish(pending, &created).unwrap();
        let mut ciphers =
            crate::crypto::CircuitCiphers::new(&session.forward_key, &session.backward_key);

        // Send a RELAY_BEGIN inside an encrypted RELAY cell.
        let begin = RelayCell {
            command: RelayCommand::Begin,
            stream_id: 1,
            data: format!("127.0.0.1:{}", echo_addr.port()).into_bytes(),
        };
        let pt = begin.encode().unwrap();
        let ct = ciphers.outbound.encrypt(&pt).unwrap();
        let mut cell = Cell::new(circuit_id, CellType::Relay);
        cell.payload.copy_from_slice(&ct);
        conn.send(&cell).await.unwrap();

        // Read responses until we see Connected, then send Data, then read echo back.
        let mut got_connected = false;
        let mut echoed = Vec::new();
        for _ in 0..10 {
            let resp = conn.recv().await.unwrap();
            if !matches!(resp.cell_type, CellType::Relay) {
                continue;
            }
            let pt = ciphers.inbound.decrypt(&resp.payload).unwrap();
            let inner = RelayCell::decode(&pt).unwrap();
            match inner.command {
                RelayCommand::Connected => {
                    got_connected = true;
                    // Send a RELAY_DATA echo request.
                    let payload = b"ping123";
                    assert!(payload.len() <= RELAY_MAX_DATA);
                    let data = RelayCell {
                        command: RelayCommand::Data,
                        stream_id: 1,
                        data: payload.to_vec(),
                    };
                    let pt = data.encode().unwrap();
                    let ct = ciphers.outbound.encrypt(&pt).unwrap();
                    let mut cell = Cell::new(circuit_id, CellType::Relay);
                    cell.payload.copy_from_slice(&ct);
                    conn.send(&cell).await.unwrap();
                }
                RelayCommand::Data if inner.stream_id == 1 => {
                    echoed.extend_from_slice(&inner.data);
                    if echoed.len() >= 7 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(got_connected, "must receive Connected before data");
        assert_eq!(
            &echoed[..],
            b"ping123",
            "relay must round-trip data through the echo server"
        );
    }
}
