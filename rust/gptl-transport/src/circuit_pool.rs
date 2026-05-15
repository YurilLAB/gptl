//! Pre-built circuit pool.
//!
//! The pool maintains `N` pre-handshaked circuits so that an incoming
//! connection can be served without paying handshake latency.  A background
//! task periodically expires stale circuits and refills the pool.

use crate::{
    bootstrap::BootstrapConfig,
    circuit::Circuit,
    guard::{GuardConfig, GuardManager},
    handshake::{client_finish, client_initiate},
    path::{PathConfig, PathSelector, RelayPath},
    relay_conn::RelayConn,
    TransportError,
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tuning parameters for the circuit pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Target number of ready circuits to maintain.
    pub size: usize,
    /// Retire a circuit once it has served this many streams.
    pub max_streams_per_circuit: usize,
    /// Retire a circuit once it is this many seconds old.
    pub max_circuit_age_secs: u64,
    /// How often (seconds) the maintenance task checks and refills the pool.
    pub refill_interval_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            size: 3,
            max_streams_per_circuit: 10,
            max_circuit_age_secs: 600,
            refill_interval_secs: 30,
        }
    }
}

// ── PooledCircuit ─────────────────────────────────────────────────────────────

/// A pre-built circuit sitting in the pool.
struct PooledCircuit {
    circuit: Circuit,
    created_at: Instant,
    stream_count: usize,
    path: RelayPath,
}

impl PooledCircuit {
    fn new(circuit: Circuit, path: RelayPath) -> Self {
        Self {
            circuit,
            created_at: Instant::now(),
            stream_count: 0,
            path,
        }
    }

    fn is_expired(&self, max_age_secs: u64) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(max_age_secs)
    }

    fn is_full(&self, max_streams: usize) -> bool {
        self.stream_count >= max_streams
    }
}

// ── CircuitPool ───────────────────────────────────────────────────────────────

/// A pool of pre-built circuits.
///
/// Normally accessed through [`CircuitPoolManager`], which wraps the pool in an
/// `Arc<Mutex<_>>` and runs a background maintenance task.
pub struct CircuitPool {
    config: PoolConfig,
    circuits: Vec<PooledCircuit>,
}

impl CircuitPool {
    /// Create an empty pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            circuits: Vec::new(),
        }
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    /// Build a new circuit along `path` and return it.
    ///
    /// Performs the ntor-lite handshake with the entry relay.  If the path has
    /// more than one hop, calls `circuit.extend()` for each subsequent relay.
    ///
    /// NOTE: `Circuit::extend` is being implemented by a parallel agent.  If it
    /// is not yet present, this function will fail to compile; add it to
    /// `circuit.rs` before building.
    async fn build_circuit(path: &RelayPath) -> Result<Circuit, TransportError> {
        let entry = path.entry();
        let relay_addr = entry.socket_addr()?;
        let relay_pubkey = entry.pubkey_bytes()?;

        // Connect.
        let mut relay_conn = RelayConn::connect(relay_addr).await?;

        // Generate a random odd circuit ID (client convention).
        let circuit_id: u32 = {
            use rand::Rng;
            let mut id: u32 = rand::thread_rng().gen();
            if id == 0 {
                id = 1;
            }
            if id.is_multiple_of(2) {
                id += 1;
            }
            id
        };

        // Handshake with entry relay.
        let (create_cell, pending) = client_initiate(circuit_id, &relay_pubkey)?;
        relay_conn.send(&create_cell).await?;
        let created = relay_conn.recv().await?;
        let keys = client_finish(pending, &created)?;

        debug!(
            "pool: handshake complete with entry relay '{}' (circuit {})",
            entry.nickname, circuit_id
        );

        let mut circuit = Circuit::new(circuit_id, keys, relay_conn);

        // Extend for each additional hop.
        // Circuit::extend is expected to be added by a parallel agent.
        // If it is not yet present, compilation will fail here with a clear
        // message rather than a runtime panic.
        for hop in path.hops.iter().skip(1) {
            circuit.extend(hop).await.map_err(|e| {
                TransportError::Protocol(format!(
                    "pool: extend to '{}' failed: {}",
                    hop.nickname, e
                ))
            })?;
            debug!(
                "pool: extended circuit {} to relay '{}'",
                circuit_id, hop.nickname
            );
        }

        Ok(circuit)
    }

    // ── Acquire / Release ─────────────────────────────────────────────────────

    /// Remove and return a usable circuit from the pool.
    ///
    /// Returns `None` if the pool is empty.
    pub async fn acquire(&mut self) -> Option<(Circuit, RelayPath)> {
        // Find the first non-expired, non-full circuit.
        let pos = self.circuits.iter().position(|c| {
            !c.is_expired(self.config.max_circuit_age_secs)
                && !c.is_full(self.config.max_streams_per_circuit)
        });
        if let Some(i) = pos {
            let pc = self.circuits.remove(i);
            debug!(
                "pool: acquired circuit (pool size now {})",
                self.circuits.len()
            );
            Some((pc.circuit, pc.path))
        } else {
            None
        }
    }

    /// Return a circuit to the pool if it is still usable.
    pub async fn release(&mut self, circuit: Circuit, path: RelayPath) {
        let mut pc = PooledCircuit::new(circuit, path);
        // Increment usage counter so we know how many streams went through it.
        pc.stream_count += 1;

        if pc.is_expired(self.config.max_circuit_age_secs)
            || pc.is_full(self.config.max_streams_per_circuit)
        {
            debug!("pool: returned circuit is stale; discarding");
            return;
        }
        self.circuits.push(pc);
        debug!(
            "pool: circuit returned to pool (size {})",
            self.circuits.len()
        );
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Build circuits until the pool reaches its target size.
    pub async fn refill(
        &mut self,
        bootstrap: &BootstrapConfig,
        path_selector: &PathSelector,
        guard: Option<&crate::bootstrap::RelayDescriptor>,
    ) {
        while self.circuits.len() < self.config.size {
            match path_selector.select_path(&bootstrap.relays, guard) {
                Err(e) => {
                    warn!("pool: path selection failed during refill: {}", e);
                    break;
                }
                Ok(path) => match Self::build_circuit(&path).await {
                    Ok(circuit) => {
                        info!(
                            "pool: built circuit via '{}' (pool size {})",
                            path.entry().nickname,
                            self.circuits.len() + 1
                        );
                        self.circuits.push(PooledCircuit::new(circuit, path));
                    }
                    Err(e) => {
                        warn!("pool: failed to build circuit during refill: {}", e);
                        break;
                    }
                },
            }
        }
    }

    /// Remove expired/full circuits then refill.
    pub async fn maintain(
        &mut self,
        bootstrap: &BootstrapConfig,
        path_selector: &PathSelector,
        guard: Option<&crate::bootstrap::RelayDescriptor>,
    ) {
        let before = self.circuits.len();
        self.circuits.retain(|c| {
            !c.is_expired(self.config.max_circuit_age_secs)
                && !c.is_full(self.config.max_streams_per_circuit)
        });
        let evicted = before - self.circuits.len();
        if evicted > 0 {
            debug!("pool: evicted {} stale circuit(s)", evicted);
        }
        self.refill(bootstrap, path_selector, guard).await;
    }

    /// Number of ready circuits in the pool.
    pub fn available_count(&self) -> usize {
        self.circuits.len()
    }
}

// ── CircuitPoolManager ────────────────────────────────────────────────────────

/// High-level pool manager: acquires circuits, returns them, and drives
/// the background maintenance loop.
pub struct CircuitPoolManager {
    pool: Arc<Mutex<CircuitPool>>,
    bootstrap: Arc<BootstrapConfig>,
    path_selector: PathSelector,
    guard_manager: Option<Mutex<GuardManager>>,
}

impl CircuitPoolManager {
    /// Create a new manager.  Call [`start_maintenance`] to begin background refilling.
    pub fn new(
        config: PoolConfig,
        path_config: PathConfig,
        bootstrap: Arc<BootstrapConfig>,
        guard_config: Option<GuardConfig>,
        guard_persist_path: Option<PathBuf>,
    ) -> Self {
        let guard_manager =
            guard_config.map(|gc| Mutex::new(GuardManager::new(gc, guard_persist_path)));

        Self {
            pool: Arc::new(Mutex::new(CircuitPool::new(config))),
            bootstrap,
            path_selector: PathSelector::new(path_config),
            guard_manager,
        }
    }

    /// Select the current entry guard (if any).
    async fn current_guard(&self) -> Option<crate::bootstrap::RelayDescriptor> {
        if let Some(ref gm_mutex) = self.guard_manager {
            let gm = gm_mutex.lock().await;
            gm.select_entry_relay(&self.bootstrap.relays).cloned()
        } else {
            None
        }
    }

    /// Acquire a circuit, building one on-demand if the pool is empty.
    pub async fn acquire_circuit(&self) -> Result<(Circuit, RelayPath), TransportError> {
        // Try the pool first.
        {
            let mut pool = self.pool.lock().await;
            if let Some(pair) = pool.acquire().await {
                return Ok(pair);
            }
        }

        // Pool is empty — build one now.
        warn!("pool: empty, building circuit on demand");
        let guard = self.current_guard().await;
        let path = self
            .path_selector
            .select_path(&self.bootstrap.relays, guard.as_ref())?;
        let circuit = CircuitPool::build_circuit(&path).await?;
        Ok((circuit, path))
    }

    /// Return a circuit to the pool (for potential reuse).
    pub async fn return_circuit(&self, circuit: Circuit, path: RelayPath) {
        let mut pool = self.pool.lock().await;
        pool.release(circuit, path).await;
    }

    /// Start the background maintenance task.
    ///
    /// Returns a `JoinHandle` that can be aborted to stop the task.
    pub fn start_maintenance(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(maintenance_loop(self))
    }
}

/// Background task: periodically evict stale circuits and refill the pool.
async fn maintenance_loop(manager: Arc<CircuitPoolManager>) {
    let interval = {
        let pool = manager.pool.lock().await;
        pool.config.refill_interval_secs
    };

    let mut ticker = tokio::time::interval(Duration::from_secs(interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        let guard = manager.current_guard().await;
        let mut pool = manager.pool.lock().await;
        pool.maintain(&manager.bootstrap, &manager.path_selector, guard.as_ref())
            .await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap::RelayDescriptor,
        handshake::{relay_respond, RelayStaticKey},
    };
    use std::sync::Arc;
    use tokio::net::TcpListener;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Spawn a fake relay that completes one ntor-lite handshake then idles.
    async fn spawn_fake_relay(key: RelayStaticKey) -> RelayDescriptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pubkey_hex = hex::encode(key.public);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let key = key.clone();
                tokio::spawn(async move {
                    let mut conn = RelayConn::new(stream);
                    // Respond to one handshake.
                    if let Ok(create) = conn.recv().await {
                        if let Ok((created, _)) = relay_respond(&create, &key) {
                            let _ = conn.send(&created).await;
                        }
                    }
                    // Hold the connection open indefinitely.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                });
            }
        });

        RelayDescriptor {
            nickname: "test-relay".into(),
            address: addr.to_string(),
            pubkey_hex,
        }
    }

    // ── pool builds a circuit ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pool_builds_circuit() {
        let key = RelayStaticKey::generate();
        let desc = spawn_fake_relay(key).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        let pool_config = PoolConfig {
            size: 1,
            ..Default::default()
        };

        let mut pool = CircuitPool::new(pool_config);
        let selector = PathSelector::new(path_config);
        pool.refill(&bootstrap, &selector, None).await;

        assert_eq!(pool.available_count(), 1);
    }

    // ── acquire removes from pool ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_pool_acquire_returns_circuit() {
        let key = RelayStaticKey::generate();
        let desc = spawn_fake_relay(key).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        let pool_config = PoolConfig {
            size: 1,
            ..Default::default()
        };

        let mut pool = CircuitPool::new(pool_config);
        let selector = PathSelector::new(path_config);
        pool.refill(&bootstrap, &selector, None).await;

        assert_eq!(pool.available_count(), 1);
        let result = pool.acquire().await;
        assert!(result.is_some());
        assert_eq!(pool.available_count(), 0);
    }

    // ── refill after acquire ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_pool_refills_after_acquire() {
        let key = RelayStaticKey::generate();
        let desc = spawn_fake_relay(key).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        let pool_config = PoolConfig {
            size: 1,
            ..Default::default()
        };

        let mut pool = CircuitPool::new(pool_config);
        let selector = PathSelector::new(path_config);
        pool.refill(&bootstrap, &selector, None).await;

        let _ = pool.acquire().await;
        assert_eq!(pool.available_count(), 0);

        pool.refill(&bootstrap, &selector, None).await;
        assert_eq!(pool.available_count(), 1);
    }

    // ── expired circuits are discarded ────────────────────────────────────────

    #[tokio::test]
    async fn test_pool_expires_old_circuits() {
        let key = RelayStaticKey::generate();
        let desc = spawn_fake_relay(key).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        // Set a 0-second max age so every circuit expires immediately.
        let pool_config = PoolConfig {
            size: 1,
            max_circuit_age_secs: 0,
            ..Default::default()
        };

        let mut pool = CircuitPool::new(pool_config);
        let selector = PathSelector::new(path_config.clone());
        pool.refill(&bootstrap, &selector, None).await;
        assert_eq!(pool.available_count(), 1);

        // Use a pool_config that won't try to refill (size 0) just to test eviction.
        pool.config.size = 0;
        pool.maintain(&bootstrap, &selector, None).await;
        assert_eq!(
            pool.available_count(),
            0,
            "expired circuit should be evicted"
        );
    }

    // ── acquire_circuit falls back to on-demand build ─────────────────────────

    #[tokio::test]
    async fn test_manager_acquire_builds_on_empty_pool() {
        let key = RelayStaticKey::generate();
        let desc = spawn_fake_relay(key).await;

        let bootstrap = Arc::new(BootstrapConfig { relays: vec![desc] });
        let path_config = PathConfig {
            num_hops: 1,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: false,
        };
        let pool_config = PoolConfig {
            size: 0,
            ..Default::default()
        }; // pool stays empty

        let manager = Arc::new(CircuitPoolManager::new(
            pool_config,
            path_config,
            bootstrap,
            None,
            None,
        ));

        let result = manager.acquire_circuit().await;
        assert!(result.is_ok(), "on-demand build should succeed");
    }
}
