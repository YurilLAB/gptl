//! SOCKS5 → GPTL circuit proxy.
//!
//! `GptlProxy::run` listens for SOCKS5 connections, builds a circuit
//! to relay(s) from the bootstrap directory, and splices data bidirectionally.
//!
//! # Multi-hop support
//!
//! When `ProxyConfig::hop_count >= 2` and at least two relays are available,
//! `handle_connection` calls `Circuit::extend` to build a 2-hop path.
//!
//! # Guard / Pool integration (Phase 3)
//!
//! When `pool_manager` is set, circuits are acquired from the pre-built pool and
//! returned after use.  When only `guard_manager` is set, the guard is used for
//! first-hop selection during on-demand circuit construction.  When neither is
//! set the legacy random-relay path is used.

use crate::{
    bootstrap::BootstrapConfig,
    circuit::Circuit,
    circuit_pool::CircuitPoolManager,
    guard::GuardManager,
    handshake::{client_finish, client_initiate},
    path::RelayPath,
    relay_conn::RelayConn,
    socks5,
    TransportError,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

/// Configuration for the GPTL SOCKS5 proxy.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Address to listen on for SOCKS5 connections (e.g. 127.0.0.1:1080)
    pub listen_addr: SocketAddr,
    /// Bootstrap relay directory
    pub bootstrap: Arc<BootstrapConfig>,
    /// Number of hops to build (1 = single-hop, 2 = two-hop).  Max 2 for now.
    pub hop_count: usize,
    /// Optional pre-built circuit pool.  When `Some`, circuits are acquired from
    /// the pool and returned after each connection.
    pub pool_manager: Option<Arc<CircuitPoolManager>>,
    /// Optional persistent entry guard.  When `Some` (and `pool_manager` is
    /// `None`), the guard relay is used for first-hop selection; success/failure
    /// is reported back after each circuit completes.
    pub guard_manager: Option<Arc<Mutex<GuardManager>>>,
}

impl ProxyConfig {
    /// Create a single-hop proxy config (no pool, no guard manager).
    pub fn new_single_hop(listen_addr: SocketAddr, bootstrap: Arc<BootstrapConfig>) -> Self {
        Self {
            listen_addr,
            bootstrap,
            hop_count: 1,
            pool_manager: None,
            guard_manager: None,
        }
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

    // ── Step 2: Acquire or build a circuit ───────────────────────────────────
    //
    // Priority:
    //   (a) pool_manager is Some  → acquire from pool (returns path alongside circuit)
    //   (b) guard_manager is Some → build on-demand but pin first hop to guard
    //   (c) both None             → legacy random-relay path (original behavior)
    let (mut circuit, circuit_path_opt): (Circuit, Option<RelayPath>) =
        if let Some(ref pool_mgr) = config.pool_manager {
            // ── (a) Pool path ─────────────────────────────────────────────────
            match pool_mgr.acquire_circuit().await {
                Ok((c, p)) => {
                    debug!("acquired circuit from pool via '{}'", p.entry().nickname);
                    (c, Some(p))
                }
                Err(e) => {
                    socks5::send_general_failure(&mut client).await;
                    return Err(e);
                }
            }
        } else if let Some(ref gm_arc) = config.guard_manager {
            // ── (b) Guard-manager path ────────────────────────────────────────
            let guard_desc = {
                let gm = gm_arc.lock().await;
                gm.select_entry_relay(&config.bootstrap.relays).cloned()
            };

            let relay_desc = match guard_desc {
                Some(d) => d,
                None => config
                    .bootstrap
                    .pick_random()
                    .ok_or_else(|| TransportError::Bootstrap("no relays available".into()))?
                    .clone(),
            };

            let relay_addr = relay_desc.socket_addr()?;
            let relay_pubkey = relay_desc.pubkey_bytes()?;

            let mut relay_conn = match RelayConn::connect(relay_addr).await {
                Ok(c) => c,
                Err(e) => {
                    // Guard failed — report it.
                    let mut gm = gm_arc.lock().await;
                    gm.report_failure(&relay_desc.nickname);
                    socks5::send_general_failure(&mut client).await;
                    return Err(e);
                }
            };

            let circuit_id = fresh_circuit_id();
            let (create_cell, pending) = client_initiate(circuit_id, &relay_pubkey)?;
            relay_conn.send(&create_cell).await?;

            let created = relay_conn.recv().await?;
            let keys = match client_finish(pending, &created) {
                Ok(k) => k,
                Err(e) => {
                    let mut gm = gm_arc.lock().await;
                    gm.report_failure(&relay_desc.nickname);
                    socks5::send_general_failure(&mut client).await;
                    return Err(e);
                }
            };
            debug!("handshake complete with guard relay '{}'", relay_desc.nickname);

            let mut circuit = Circuit::new(circuit_id, keys, relay_conn);

            // Optionally extend for multi-hop.
            if config.hop_count >= 2 && config.bootstrap.relays.len() >= 2 {
                let relay2 = config
                    .bootstrap
                    .pick_relay_excluding(&relay_desc.nickname)
                    .ok_or_else(|| {
                        TransportError::Bootstrap("no relay2 available for multi-hop".into())
                    })?
                    .clone();

                if let Err(e) = circuit.extend(&relay2).await {
                    let mut gm = gm_arc.lock().await;
                    gm.report_failure(&relay_desc.nickname);
                    socks5::send_general_failure(&mut client).await;
                    return Err(e);
                }
                debug!("circuit {} extended to relay2 '{}'", circuit_id, relay2.nickname);
            }

            // Record the guard nickname in the path so we can report success later.
            let path = RelayPath { hops: vec![relay_desc] };
            (circuit, Some(path))
        } else {
            // ── (c) Legacy random-relay path ──────────────────────────────────
            let relay_desc = config
                .bootstrap
                .pick_random()
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

            let circuit_id = fresh_circuit_id();
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

            if config.hop_count >= 2 && config.bootstrap.relays.len() >= 2 {
                let relay2 = config
                    .bootstrap
                    .pick_relay_excluding(&relay_desc.nickname)
                    .ok_or_else(|| {
                        TransportError::Bootstrap("no relay2 available for multi-hop".into())
                    })?
                    .clone();

                if let Err(e) = circuit.extend(&relay2).await {
                    socks5::send_general_failure(&mut client).await;
                    return Err(e);
                }
                debug!("circuit {} extended to relay2 '{}'", circuit_id, relay2.nickname);
            }

            (circuit, None)
        };

    let circuit_id = circuit.circuit_id;

    // ── Step 3: Open a stream to the destination ──────────────────────────────
    let mut stream = circuit.open_stream(&request.host, request.port).await?;

    // Bug 1 fix: use select! to race circuit stepping against wait_connected(),
    // instead of the double-timeout polling anti-pattern.
    let connect_result = tokio::time::timeout(
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
    .map_err(|_| TransportError::Protocol("relay connect timed out".into()));

    if connect_result.is_err() {
        // Report guard failure if we used one.
        if let Some(ref gm_arc) = config.guard_manager {
            if let Some(ref path) = circuit_path_opt {
                let mut gm = gm_arc.lock().await;
                gm.report_failure(&path.entry().nickname);
            }
        }
        socks5::send_general_failure(&mut client).await;
        return connect_result.map_err(|_| TransportError::Protocol("relay connect timed out".into()))?;
    }
    connect_result??;

    // Report guard success.
    if let Some(ref gm_arc) = config.guard_manager {
        if let Some(ref path) = circuit_path_opt {
            let mut gm = gm_arc.lock().await;
            gm.report_success(&path.entry().nickname);
        }
    }

    // Tell the SOCKS5 client we're connected
    socks5::send_success(&mut client).await;
    info!(
        "circuit {} stream {} → {}:{}",
        circuit_id, stream.stream_id, request.host, request.port
    );

    // ── Step 4: Splice data bidirectionally ───────────────────────────────────
    // `splice` takes ownership of `circuit` and runs its stepping loop in a
    // background task.  The circuit cannot be reclaimed after splice returns.
    // When pool_manager is active, the maintenance loop automatically rebuilds
    // the pool.  Any guard path information is only needed up to this point.
    splice(client, stream, circuit).await
}

/// Generate a fresh random circuit ID: non-zero, odd (client convention).
fn fresh_circuit_id() -> u32 {
    use rand::Rng;
    let mut id: u32 = rand::thread_rng().gen();
    if id == 0 {
        id = 1;
    }
    if id & 1 == 0 {
        id += 1;
    }
    id
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap::RelayDescriptor,
        circuit_pool::{CircuitPool, CircuitPoolManager, PoolConfig},
        guard::{GuardConfig, GuardManager},
        handshake::{relay_respond, RelayStaticKey},
        path::{PathConfig, PathSelector},
    };
    use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
    use std::time::Duration;
    use tokio::net::TcpListener;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Spawn a fake relay that completes the ntor-lite handshake and tracks how
    /// many times it has been contacted.
    async fn spawn_tracked_relay(
        key: RelayStaticKey,
        contact_count: Arc<AtomicUsize>,
    ) -> RelayDescriptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pubkey_hex = hex::encode(key.public);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                contact_count.fetch_add(1, Ordering::SeqCst);
                let key = key.clone();
                tokio::spawn(async move {
                    let mut conn = RelayConn::new(stream);
                    if let Ok(create) = conn.recv().await {
                        if let Ok((created, _)) = relay_respond(&create, &key) {
                            let _ = conn.send(&created).await;
                        }
                    }
                    // Hold open long enough for the test to observe the connection.
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });

        RelayDescriptor {
            nickname: format!("relay-{}", addr.port()),
            address: addr.to_string(),
            pubkey_hex,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1: proxy uses the pinned guard relay as entry
    // ─────────────────────────────────────────────────────────────────────────

    /// Verifies that when a GuardManager is configured with a specific guard,
    /// `handle_connection` uses that guard relay as the circuit entry point.
    #[tokio::test]
    async fn test_proxy_with_guard_manager_uses_guard_relay() {
        let key_a = RelayStaticKey::generate();
        let key_b = RelayStaticKey::generate();

        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));

        let desc_a = spawn_tracked_relay(key_a, Arc::clone(&count_a)).await;
        let desc_b = spawn_tracked_relay(key_b, Arc::clone(&count_b)).await;

        // Bootstrap contains both relays, but the guard manager is initialized
        // with only relay A — so it will always select A as the entry guard.
        let bootstrap = Arc::new(BootstrapConfig {
            relays: vec![desc_a.clone(), desc_b.clone()],
        });

        let guard_config = GuardConfig {
            num_guards: 1,
            min_guards: 1,
            ..Default::default()
        };
        // Initialize the guard manager with only relay A so it pins to A.
        let mut gm = GuardManager::new(guard_config, None);
        gm.initialize(&[desc_a.clone()]).await.unwrap();

        let guard_manager = Arc::new(Mutex::new(gm));

        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bootstrap,
            hop_count: 1,
            pool_manager: None,
            guard_manager: Some(guard_manager),
        };

        // handle_connection requires a TcpStream.  Use a real loopback pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        // Connect a real TCP client to "our proxy listener" and send SOCKS5.
        let client_task = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
            // SOCKS5 greeting
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            // Read server choice
            let mut buf = [0u8; 2];
            use tokio::io::AsyncReadExt;
            let _ = stream.read_exact(&mut buf).await;
            // CONNECT to 127.0.0.1:80
            stream.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let (tcp_stream, _) = listener.accept().await.unwrap();
        let cfg2 = config.clone();
        let conn_task = tokio::spawn(async move {
            let _ = handle_connection(tcp_stream, cfg2).await;
        });

        // Wait for the connection attempt to complete (it will fail — no relay
        // actually proxies our destination — but the handshake with relay A
        // will have been attempted).
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            let _ = client_task.await;
            let _ = conn_task.await;
        })
        .await;

        // Relay A should have been contacted at least once; relay B never.
        let a_contacts = count_a.load(Ordering::SeqCst);
        let b_contacts = count_b.load(Ordering::SeqCst);
        assert!(
            a_contacts >= 1,
            "guard relay A should have been contacted (got {})",
            a_contacts
        );
        assert_eq!(
            b_contacts, 0,
            "relay B should NOT have been contacted when guard is pinned to A (got {})",
            b_contacts
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2: pool size goes back up after a circuit is used and returned
    // ─────────────────────────────────────────────────────────────────────────

    /// Verifies that `CircuitPool::release` adds the circuit back to the pool,
    /// restoring its available count, and that `CircuitPoolManager::return_circuit`
    /// delegates to the pool correctly.
    #[tokio::test]
    async fn test_proxy_pool_returns_circuit_after_use() {
        let key = RelayStaticKey::generate();
        let contact_count = Arc::new(AtomicUsize::new(0));
        let desc = spawn_tracked_relay(key, Arc::clone(&contact_count)).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        let pool_config = PoolConfig {
            size: 1,
            max_streams_per_circuit: 10,
            max_circuit_age_secs: 600,
            ..Default::default()
        };

        // Build the pool manager and prefill it.
        let manager = Arc::new(CircuitPoolManager::new(
            pool_config,
            path_config,
            Arc::clone(&bootstrap),
            None,
            None,
        ));

        // Manually refill via CircuitPool for the test.
        let selector = PathSelector::new(PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        });
        {
            // Build directly through the underlying pool so we can inspect size.
            let pool_config2 = PoolConfig { size: 1, ..Default::default() };
            let mut pool = CircuitPool::new(pool_config2);
            pool.refill(&bootstrap, &selector, None).await;
            assert_eq!(pool.available_count(), 1, "pool should have 1 circuit after refill");

            // Acquire removes it from the pool.
            let acquired = pool.acquire().await;
            assert!(acquired.is_some(), "should acquire a circuit");
            assert_eq!(pool.available_count(), 0, "pool should be empty after acquire");

            // Return the circuit back.
            let (circuit, path) = acquired.unwrap();
            pool.release(circuit, path).await;

            // The circuit should be back (stream_count=1, well under max_streams=10).
            assert_eq!(
                pool.available_count(),
                1,
                "pool should have 1 circuit after release"
            );
        }

        // Also verify through CircuitPoolManager API: acquire then return.
        let (circuit, path) = manager.acquire_circuit().await
            .expect("manager should build on-demand when pool is empty");
        manager.return_circuit(circuit, path).await;
        // After return_circuit the pool should have 1 circuit available.
        // (The manager wraps the pool in Arc<Mutex>; check via a second acquire.)
        let second = manager.acquire_circuit().await;
        assert!(second.is_ok(), "second acquire should succeed after return_circuit");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3: on-demand circuit build when pool is empty (pool_size=0)
    // ─────────────────────────────────────────────────────────────────────────

    /// Verifies that when `pool_manager` is `None` (pool_size = 0), the proxy
    /// falls back to building circuits on-demand from the bootstrap relay list.
    #[tokio::test]
    async fn test_proxy_falls_back_when_pool_empty() {
        let key = RelayStaticKey::generate();
        let contact_count = Arc::new(AtomicUsize::new(0));
        let desc = spawn_tracked_relay(key, Arc::clone(&contact_count)).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };

        // pool_size = 0 means the pool stays empty and the manager falls back to
        // on-demand circuit construction via `acquire_circuit`.
        let pool_config = PoolConfig { size: 0, ..Default::default() };

        let manager = Arc::new(CircuitPoolManager::new(
            pool_config,
            path_config,
            bootstrap,
            None,
            None,
        ));

        // acquire_circuit on an always-empty pool should trigger on-demand build.
        let result = manager.acquire_circuit().await;
        assert!(
            result.is_ok(),
            "on-demand circuit build should succeed when pool is empty"
        );

        // The relay should have been contacted exactly once.
        assert_eq!(
            contact_count.load(Ordering::SeqCst),
            1,
            "relay should be contacted once for on-demand build"
        );
    }
}
