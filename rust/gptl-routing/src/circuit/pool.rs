//! Circuit Pool Module
//!
//! Manages a pool of pre-built ready circuits for immediate use.
//! Based on Tor's circuit pre-building strategy to reduce connection latency.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, info, trace, warn};

use super::health::CircuitHealthMonitor;

/// Unique circuit identifier
pub type CircuitId = u64;

/// Circuit state in the pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolCircuitState {
    /// Circuit is being built
    Building,
    /// Circuit is ready for use
    Ready,
    /// Circuit is currently in use
    InUse,
    /// Circuit is being refreshed
    Refreshing,
    /// Circuit is marked for removal
    Retiring,
}

/// Circuit information in the pool
#[derive(Debug, Clone)]
pub struct PoolCircuit {
    /// Circuit ID
    pub id: CircuitId,
    /// Current state
    pub state: PoolCircuitState,
    /// Circuit creation time
    pub created_at: Instant,
    /// Time when circuit became ready
    pub ready_at: Option<Instant>,
    /// Last used time
    pub last_used: Option<Instant>,
    /// Number of times used
    pub use_count: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Circuit path (relay IDs)
    pub path: Vec<String>,
    /// Circuit bandwidth estimate (bytes/sec)
    pub bandwidth_estimate: u64,
    /// Whether this circuit is dirty (has been used)
    pub is_dirty: bool,
}

impl PoolCircuit {
    /// Create a new pool circuit
    pub fn new(id: CircuitId, path: Vec<String>) -> Self {
        Self {
            id,
            state: PoolCircuitState::Building,
            created_at: Instant::now(),
            ready_at: None,
            last_used: None,
            use_count: 0,
            bytes_transferred: 0,
            path,
            bandwidth_estimate: 0,
            is_dirty: false,
        }
    }

    /// Mark circuit as ready
    pub fn mark_ready(&mut self) {
        self.state = PoolCircuitState::Ready;
        self.ready_at = Some(Instant::now());
    }

    /// Mark circuit as in use
    pub fn mark_in_use(&mut self) {
        self.state = PoolCircuitState::InUse;
        self.last_used = Some(Instant::now());
        self.use_count += 1;
        self.is_dirty = true;
    }

    /// Mark circuit as available
    pub fn mark_available(&mut self) {
        if self.state == PoolCircuitState::InUse {
            self.state = PoolCircuitState::Ready;
        }
    }

    /// Mark circuit for retirement
    pub fn mark_retiring(&mut self) {
        self.state = PoolCircuitState::Retiring;
    }

    /// Get time since circuit was built
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Get time since last use
    pub fn idle_time(&self) -> Option<Duration> {
        self.last_used.map(|t| Instant::now().duration_since(t))
    }

    /// Check if circuit needs refresh based on age
    pub fn needs_refresh(&self, max_age: Duration) -> bool {
        self.age() > max_age && self.state == PoolCircuitState::Ready
    }

    /// Check if circuit is available for use
    pub fn is_available(&self) -> bool {
        self.state == PoolCircuitState::Ready
    }
}

/// Configuration for circuit pool
#[derive(Debug, Clone)]
pub struct CircuitPoolConfig {
    /// Minimum number of ready circuits to maintain
    pub min_pool_size: usize,
    /// Maximum number of circuits in the pool
    pub max_pool_size: usize,
    /// Number of circuits to build in advance
    pub pre_build_count: usize,
    /// Maximum circuit age before refresh
    pub max_circuit_age: Duration,
    /// Maximum idle time before retirement
    pub max_idle_time: Duration,
    /// Maximum use count before retirement
    pub max_use_count: u64,
    /// Maximum bytes before retirement
    pub max_bytes_transferred: u64,
    /// Circuit build timeout
    pub build_timeout: Duration,
    /// Pool refill check interval
    pub refill_interval: Duration,
    /// Whether to enable background building
    pub enable_background_build: bool,
    /// Maximum concurrent circuit builds
    pub max_concurrent_builds: usize,
}

impl Default for CircuitPoolConfig {
    fn default() -> Self {
        Self {
            min_pool_size: 3,
            max_pool_size: 10,
            pre_build_count: 5,
            max_circuit_age: Duration::from_secs(600), // 10 minutes
            max_idle_time: Duration::from_secs(300),   // 5 minutes
            max_use_count: 100,
            max_bytes_transferred: 100 * 1024 * 1024, // 100 MB
            build_timeout: Duration::from_secs(30),
            refill_interval: Duration::from_secs(10),
            enable_background_build: true,
            max_concurrent_builds: 2,
        }
    }
}

/// Events emitted by the circuit pool
#[derive(Debug, Clone)]
pub enum PoolEvent {
    /// Circuit build started
    CircuitBuilding { circuit_id: CircuitId },
    /// Circuit is ready
    CircuitReady { circuit_id: CircuitId },
    /// Circuit build failed
    CircuitBuildFailed {
        circuit_id: CircuitId,
        error: String,
    },
    /// Circuit acquired for use
    CircuitAcquired { circuit_id: CircuitId },
    /// Circuit released back to pool
    CircuitReleased { circuit_id: CircuitId },
    /// Circuit retired
    CircuitRetired {
        circuit_id: CircuitId,
        reason: RetireReason,
    },
    /// Pool refilled
    PoolRefilled { count: usize },
    /// Pool is empty
    PoolEmpty,
    /// Circuit refresh started
    CircuitRefreshing { circuit_id: CircuitId },
}

/// Reason for circuit retirement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetireReason {
    /// Circuit too old
    Age,
    /// Circuit idle too long
    Idle,
    /// Too many uses
    UseCount,
    /// Too many bytes transferred
    BytesTransferred,
    /// Health check failure
    HealthCheck,
    /// Explicit closure
    Explicit,
}

/// Circuit pool for managing ready circuits
pub struct CircuitPool {
    /// Configuration
    config: CircuitPoolConfig,
    /// Circuits in the pool
    circuits: Arc<RwLock<HashMap<CircuitId, PoolCircuit>>>,
    /// Queue of available circuit IDs
    available_queue: Arc<RwLock<VecDeque<CircuitId>>>,
    /// Next circuit ID
    next_id: Arc<RwLock<u64>>,
    /// Health monitor reference
    health_monitor: Arc<CircuitHealthMonitor>,
    /// Event sender
    event_sender: Option<mpsc::Sender<PoolEvent>>,
    /// Build semaphore to limit concurrent builds
    build_semaphore: Arc<Semaphore>,
    /// Circuit builder function
    builder: Arc<dyn CircuitBuilder>,
}

/// Trait for building circuits
#[async_trait::async_trait]
pub trait CircuitBuilder: Send + Sync {
    /// Build a new circuit
    async fn build_circuit(&self, circuit_id: CircuitId) -> Result<Vec<String>, PoolError>;

    /// Test if a circuit is working
    async fn test_circuit(&self, path: &[String]) -> Result<bool, PoolError>;

    /// Close a circuit
    async fn close_circuit(&self, circuit_id: CircuitId) -> Result<(), PoolError>;
}

/// Errors that can occur in the pool
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("Circuit build timeout")]
    BuildTimeout,
    #[error("Circuit build failed: {0}")]
    BuildFailed(String),
    #[error("Pool is empty")]
    PoolEmpty,
    #[error("Pool is at capacity")]
    PoolAtCapacity,
    #[error("Circuit not found: {0}")]
    CircuitNotFound(CircuitId),
    #[error("Circuit not available: {0}")]
    CircuitNotAvailable(CircuitId),
    #[error("Health check failed for circuit {0}")]
    HealthCheckFailed(CircuitId),
    #[error("Too many concurrent builds")]
    TooManyBuilds,
}

impl CircuitPool {
    /// Create a new circuit pool
    pub fn new(
        config: CircuitPoolConfig,
        health_monitor: Arc<CircuitHealthMonitor>,
        builder: Arc<dyn CircuitBuilder>,
    ) -> Self {
        let build_semaphore = Arc::new(Semaphore::new(config.max_concurrent_builds));

        Self {
            config,
            circuits: Arc::new(RwLock::new(HashMap::new())),
            available_queue: Arc::new(RwLock::new(VecDeque::new())),
            next_id: Arc::new(RwLock::new(1)),
            health_monitor,
            event_sender: None,
            build_semaphore,
            builder,
        }
    }

    /// Set event sender
    pub fn with_event_sender(mut self, sender: mpsc::Sender<PoolEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Initialize the pool with pre-built circuits
    pub async fn initialize(&self) -> Result<(), PoolError> {
        info!(
            "Initializing circuit pool with {} pre-built circuits",
            self.config.pre_build_count
        );

        // Build initial circuits
        for _ in 0..self.config.pre_build_count {
            self.build_circuit().await?;
        }

        // Start background tasks
        if self.config.enable_background_build {
            self.start_background_tasks();
        }

        info!("Circuit pool initialized");
        Ok(())
    }

    /// Get a circuit from the pool
    pub async fn acquire_circuit(&self) -> Result<CircuitId, PoolError> {
        // Try to get an available circuit with health check
        loop {
            let circuit_id = {
                let mut queue = self.available_queue.write().await;
                queue.pop_front()
            };

            match circuit_id {
                Some(id) => {
                    // Check health before returning
                    if self.health_monitor.needs_rotation(id).await {
                        // Retire this circuit and continue to get another
                        let _ = self.retire_circuit(id, RetireReason::HealthCheck).await;
                        continue;
                    }

                    // Mark as in use
                    let mut circuits = self.circuits.write().await;
                    if let Some(circuit) = circuits.get_mut(&id) {
                        circuit.mark_in_use();
                    }
                    drop(circuits);

                    self.send_event(PoolEvent::CircuitAcquired { circuit_id: id })
                        .await;

                    // Trigger refill if needed
                    self.check_and_refill().await;

                    return Ok(id);
                }
                None => break,
            }
        }

        // No available circuit - try to build one immediately
        warn!("Pool is empty, building circuit on-demand");
        self.send_event(PoolEvent::PoolEmpty).await;

        match self.build_circuit().await {
            Ok(id) => {
                let mut circuits = self.circuits.write().await;
                if let Some(circuit) = circuits.get_mut(&id) {
                    circuit.mark_in_use();
                }
                drop(circuits);

                self.send_event(PoolEvent::CircuitAcquired { circuit_id: id })
                    .await;
                Ok(id)
            }
            Err(_e) => Err(PoolError::PoolEmpty),
        }
    }

    /// Return a circuit to the pool
    pub async fn release_circuit(&self, circuit_id: CircuitId) -> Result<(), PoolError> {
        let mut circuits = self.circuits.write().await;

        let Some(circuit) = circuits.get_mut(&circuit_id) else {
            return Err(PoolError::CircuitNotFound(circuit_id));
        };

        // Check if circuit should be retired
        if self.should_retire(circuit) {
            drop(circuits);
            return self
                .retire_circuit(circuit_id, RetireReason::UseCount)
                .await;
        }

        circuit.mark_available();
        drop(circuits);

        // Add back to available queue
        let mut queue = self.available_queue.write().await;
        queue.push_back(circuit_id);
        drop(queue);

        self.send_event(PoolEvent::CircuitReleased { circuit_id })
            .await;

        Ok(())
    }

    /// Retire a circuit
    pub async fn retire_circuit(
        &self,
        circuit_id: CircuitId,
        reason: RetireReason,
    ) -> Result<(), PoolError> {
        let mut circuits = self.circuits.write().await;

        let Some(mut circuit) = circuits.remove(&circuit_id) else {
            return Err(PoolError::CircuitNotFound(circuit_id));
        };

        circuit.mark_retiring();
        drop(circuits);

        // Remove from available queue if present
        let mut queue = self.available_queue.write().await;
        queue.retain(|&id| id != circuit_id);
        drop(queue);

        // Unregister from health monitor
        self.health_monitor.unregister_circuit(circuit_id).await;

        // Close the circuit
        if let Err(e) = self.builder.close_circuit(circuit_id).await {
            warn!(circuit_id, error = %e, "Error closing retired circuit");
        }

        self.send_event(PoolEvent::CircuitRetired { circuit_id, reason })
            .await;

        debug!(circuit_id, reason = ?reason, "Circuit retired");

        // Trigger refill
        self.check_and_refill().await;

        Ok(())
    }

    /// Get pool statistics
    pub async fn get_statistics(&self) -> PoolStatistics {
        let circuits = self.circuits.read().await;
        let available = self.available_queue.read().await;

        let mut building = 0;
        let mut ready = 0;
        let mut in_use = 0;
        let mut retiring = 0;
        let mut total_bytes = 0u64;
        let mut total_uses = 0u64;

        for circuit in circuits.values() {
            match circuit.state {
                PoolCircuitState::Building => building += 1,
                PoolCircuitState::Ready => ready += 1,
                PoolCircuitState::InUse => in_use += 1,
                PoolCircuitState::Retiring => retiring += 1,
                _ => {}
            }
            total_bytes += circuit.bytes_transferred;
            total_uses += circuit.use_count;
        }

        PoolStatistics {
            total_circuits: circuits.len(),
            building_circuits: building,
            ready_circuits: ready,
            in_use_circuits: in_use,
            retiring_circuits: retiring,
            available_in_queue: available.len(),
            total_bytes_transferred: total_bytes,
            total_circuit_uses: total_uses,
        }
    }

    /// Get circuit information
    pub async fn get_circuit(&self, circuit_id: CircuitId) -> Option<PoolCircuit> {
        let circuits = self.circuits.read().await;
        circuits.get(&circuit_id).cloned()
    }

    /// Update circuit usage stats
    pub async fn update_circuit_usage(
        &self,
        circuit_id: CircuitId,
        bytes_transferred: u64,
    ) -> Result<(), PoolError> {
        let mut circuits = self.circuits.write().await;

        let Some(circuit) = circuits.get_mut(&circuit_id) else {
            return Err(PoolError::CircuitNotFound(circuit_id));
        };

        circuit.bytes_transferred += bytes_transferred;

        // Check if should retire due to bytes
        if circuit.bytes_transferred >= self.config.max_bytes_transferred {
            drop(circuits);
            return self
                .retire_circuit(circuit_id, RetireReason::BytesTransferred)
                .await;
        }

        Ok(())
    }

    /// Build a new circuit
    async fn build_circuit(&self) -> Result<CircuitId, PoolError> {
        // Check pool capacity
        let circuits = self.circuits.read().await;
        if circuits.len() >= self.config.max_pool_size {
            return Err(PoolError::PoolAtCapacity);
        }
        drop(circuits);

        // Acquire build permit
        let _permit = self
            .build_semaphore
            .acquire()
            .await
            .map_err(|_| PoolError::TooManyBuilds)?;

        // Generate new circuit ID
        let circuit_id = {
            let mut next_id = self.next_id.write().await;
            let id = *next_id;
            *next_id += 1;
            id
        };

        // Register with health monitor
        self.health_monitor.register_circuit(circuit_id).await;

        // Create placeholder circuit
        let placeholder = PoolCircuit::new(circuit_id, Vec::new());

        {
            let mut circuits = self.circuits.write().await;
            circuits.insert(circuit_id, placeholder);
        }

        self.send_event(PoolEvent::CircuitBuilding { circuit_id })
            .await;

        // Build circuit with timeout
        let build_result = tokio::time::timeout(
            self.config.build_timeout,
            self.builder.build_circuit(circuit_id),
        )
        .await;

        match build_result {
            Ok(Ok(path)) => {
                // Update circuit
                let mut circuits = self.circuits.write().await;
                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                    circuit.path = path;
                    circuit.mark_ready();
                }
                drop(circuits);

                // Add to available queue
                let mut queue = self.available_queue.write().await;
                queue.push_back(circuit_id);
                drop(queue);

                self.send_event(PoolEvent::CircuitReady { circuit_id })
                    .await;

                debug!(circuit_id, "Circuit built successfully");
                Ok(circuit_id)
            }
            Ok(Err(e)) => {
                // Build failed
                let mut circuits = self.circuits.write().await;
                circuits.remove(&circuit_id);
                drop(circuits);

                self.health_monitor.unregister_circuit(circuit_id).await;

                self.send_event(PoolEvent::CircuitBuildFailed {
                    circuit_id,
                    error: e.to_string(),
                })
                .await;

                Err(PoolError::BuildFailed(e.to_string()))
            }
            Err(_) => {
                // Timeout
                let mut circuits = self.circuits.write().await;
                circuits.remove(&circuit_id);
                drop(circuits);

                self.health_monitor.unregister_circuit(circuit_id).await;

                self.send_event(PoolEvent::CircuitBuildFailed {
                    circuit_id,
                    error: "Timeout".to_string(),
                })
                .await;

                Err(PoolError::BuildTimeout)
            }
        }
    }

    /// Check if a circuit should be retired
    fn should_retire(&self, circuit: &PoolCircuit) -> bool {
        // Check age
        if circuit.age() > self.config.max_circuit_age {
            return true;
        }

        // Check idle time
        if let Some(idle) = circuit.idle_time() {
            if idle > self.config.max_idle_time {
                return true;
            }
        }

        // Check use count
        if circuit.use_count >= self.config.max_use_count {
            return true;
        }

        // Check bytes transferred
        if circuit.bytes_transferred >= self.config.max_bytes_transferred {
            return true;
        }

        false
    }

    /// Check pool level and refill if needed
    async fn check_and_refill(&self) {
        let available = self.available_queue.read().await.len();

        if available < self.config.min_pool_size {
            let needed = self.config.min_pool_size - available;

            debug!(needed, "Refilling circuit pool");

            let mut built = 0;
            for _ in 0..needed {
                match self.build_circuit().await {
                    Ok(_) => built += 1,
                    Err(e) => {
                        warn!(error = %e, "Failed to build circuit during refill");
                        break;
                    }
                }
            }

            if built > 0 {
                self.send_event(PoolEvent::PoolRefilled { count: built })
                    .await;
            }
        }
    }

    /// Start background maintenance tasks
    fn start_background_tasks(&self) {
        self.start_refill_task();
        self.start_refresh_task();
    }

    /// Start background refill task
    fn start_refill_task(&self) {
        let circuits = self.circuits.clone();
        let available = self.available_queue.clone();
        let config = self.config.clone();
        let health_monitor = self.health_monitor.clone();
        let builder = self.builder.clone();
        let build_semaphore = self.build_semaphore.clone();
        let event_sender = self.event_sender.clone();
        let next_id = self.next_id.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.refill_interval);

            loop {
                interval.tick().await;

                // Check available count
                let available_count = available.read().await.len();

                if available_count < config.min_pool_size {
                    let needed = config.min_pool_size - available_count;

                    for _ in 0..needed {
                        // Check capacity
                        if circuits.read().await.len() >= config.max_pool_size {
                            break;
                        }

                        // Try to acquire build permit
                        let Ok(_permit) = build_semaphore.try_acquire() else {
                            break;
                        };

                        // Generate circuit ID
                        let circuit_id = {
                            let mut id = next_id.write().await;
                            let cid = *id;
                            *id += 1;
                            cid
                        };

                        // Register with health monitor
                        health_monitor.register_circuit(circuit_id).await;

                        // Build circuit
                        if let Ok(Ok(path)) = tokio::time::timeout(
                            config.build_timeout,
                            builder.build_circuit(circuit_id),
                        )
                        .await
                        {
                            let circuit = PoolCircuit {
                                id: circuit_id,
                                state: PoolCircuitState::Ready,
                                created_at: Instant::now(),
                                ready_at: Some(Instant::now()),
                                last_used: None,
                                use_count: 0,
                                bytes_transferred: 0,
                                path,
                                bandwidth_estimate: 0,
                                is_dirty: false,
                            };

                            circuits.write().await.insert(circuit_id, circuit);
                            available.write().await.push_back(circuit_id);

                            if let Some(ref sender) = event_sender {
                                let _ = sender.send(PoolEvent::CircuitReady { circuit_id }).await;
                            }
                        } else {
                            health_monitor.unregister_circuit(circuit_id).await;
                        }
                    }
                }
            }
        });
    }

    /// Start background refresh task
    fn start_refresh_task(&self) {
        let circuits = self.circuits.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));

            loop {
                interval.tick().await;

                let _now = Instant::now();
                let mut to_refresh = Vec::new();

                // Find circuits needing refresh
                {
                    let circuits_guard = circuits.read().await;
                    for (id, circuit) in circuits_guard.iter() {
                        if circuit.needs_refresh(config.max_circuit_age) {
                            to_refresh.push(*id);
                        }
                    }
                }

                // Mark circuits for refresh (they'll be replaced when used)
                for id in to_refresh {
                    let mut circuits_guard = circuits.write().await;
                    if let Some(circuit) = circuits_guard.get_mut(&id) {
                        circuit.state = PoolCircuitState::Refreshing;
                    }
                }

                trace!("Refresh check completed");
            }
        });
    }

    /// Send event if sender is configured
    async fn send_event(&self, event: PoolEvent) {
        if let Some(ref sender) = self.event_sender {
            let _ = sender.send(event).await;
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStatistics {
    /// Total number of circuits
    pub total_circuits: usize,
    /// Number of circuits being built
    pub building_circuits: usize,
    /// Number of ready circuits
    pub ready_circuits: usize,
    /// Number of circuits in use
    pub in_use_circuits: usize,
    /// Number of circuits being retired
    pub retiring_circuits: usize,
    /// Number available in queue
    pub available_in_queue: usize,
    /// Total bytes transferred through pool
    pub total_bytes_transferred: u64,
    /// Total circuit uses
    pub total_circuit_uses: u64,
}

/// Mock circuit builder for testing
#[cfg(test)]
pub struct MockCircuitBuilder {
    pub success_rate: f64,
    pub build_delay: Duration,
}

#[cfg(test)]
#[async_trait::async_trait]
impl CircuitBuilder for MockCircuitBuilder {
    async fn build_circuit(&self, circuit_id: CircuitId) -> Result<Vec<String>, PoolError> {
        tokio::time::sleep(self.build_delay).await;

        if rand::random::<f64>() < self.success_rate {
            Ok(vec![
                format!("relay1_{}", circuit_id),
                format!("relay2_{}", circuit_id),
                format!("relay3_{}", circuit_id),
            ])
        } else {
            Err(PoolError::BuildFailed("Random failure".to_string()))
        }
    }

    async fn test_circuit(&self, _path: &[String]) -> Result<bool, PoolError> {
        Ok(true)
    }

    async fn close_circuit(&self, _circuit_id: CircuitId) -> Result<(), PoolError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_circuit_states() {
        let mut circuit = PoolCircuit::new(1, vec!["r1".to_string(), "r2".to_string()]);

        assert_eq!(circuit.state, PoolCircuitState::Building);
        assert!(!circuit.is_available());

        circuit.mark_ready();
        assert_eq!(circuit.state, PoolCircuitState::Ready);
        assert!(circuit.is_available());

        circuit.mark_in_use();
        assert_eq!(circuit.state, PoolCircuitState::InUse);
        assert!(!circuit.is_available());
        assert_eq!(circuit.use_count, 1);
        assert!(circuit.is_dirty);

        circuit.mark_available();
        assert_eq!(circuit.state, PoolCircuitState::Ready);
    }

    #[test]
    fn test_pool_circuit_age() {
        let circuit = PoolCircuit::new(1, vec!["r1".to_string()]);

        // Circuit should be fresh
        assert!(!circuit.needs_refresh(Duration::from_secs(60)));

        // Age check should work
        assert!(circuit.age() < Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_circuit_pool_basic() {
        let config = CircuitPoolConfig {
            min_pool_size: 2,
            max_pool_size: 5,
            pre_build_count: 2,
            build_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let health_monitor = Arc::new(CircuitHealthMonitor::new());
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let pool = CircuitPool::new(config, health_monitor, builder);
        pool.initialize().await.unwrap();

        // Check statistics
        let stats = pool.get_statistics().await;
        assert_eq!(stats.ready_circuits, 2);
    }

    #[tokio::test]
    async fn test_circuit_pool_acquire_release() {
        let config = CircuitPoolConfig {
            min_pool_size: 2,
            max_pool_size: 5,
            pre_build_count: 2,
            build_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let health_monitor = Arc::new(CircuitHealthMonitor::new());
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let pool = CircuitPool::new(config, health_monitor, builder);
        pool.initialize().await.unwrap();

        // Acquire a circuit
        let circuit_id = pool.acquire_circuit().await.unwrap();

        let stats = pool.get_statistics().await;
        assert_eq!(stats.in_use_circuits, 1);
        // Acquiring triggers check_and_refill, which builds 1 new circuit to keep the
        // pool at min_pool_size=2, so ready_circuits stays at 2.
        assert_eq!(stats.ready_circuits, 2);

        // Release the circuit
        pool.release_circuit(circuit_id).await.unwrap();

        let stats = pool.get_statistics().await;
        assert_eq!(stats.in_use_circuits, 0);
        // After release the circuit is back in ready state; pool now has 3 ready circuits.
        assert_eq!(stats.ready_circuits, 3);
    }

    #[tokio::test]
    async fn test_circuit_pool_retire() {
        let config = CircuitPoolConfig {
            min_pool_size: 2,
            max_pool_size: 5,
            pre_build_count: 2,
            max_use_count: 3,
            ..Default::default()
        };

        let health_monitor = Arc::new(CircuitHealthMonitor::new());
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let pool = CircuitPool::new(config, health_monitor, builder);
        pool.initialize().await.unwrap();

        // Acquire and release circuit multiple times
        let circuit_id = pool.acquire_circuit().await.unwrap();
        pool.release_circuit(circuit_id).await.unwrap();

        let circuit_id = pool.acquire_circuit().await.unwrap();
        pool.release_circuit(circuit_id).await.unwrap();

        let circuit_id = pool.acquire_circuit().await.unwrap();
        pool.release_circuit(circuit_id).await.unwrap();

        // Fourth release should retire the circuit due to use count
        let circuit_id = pool.acquire_circuit().await.unwrap();
        pool.release_circuit(circuit_id).await.unwrap();
    }

    #[tokio::test]
    async fn test_circuit_pool_empty_build_on_demand() {
        let config = CircuitPoolConfig {
            min_pool_size: 0,
            max_pool_size: 5,
            pre_build_count: 0,
            build_timeout: Duration::from_secs(5),
            ..Default::default()
        };

        let health_monitor = Arc::new(CircuitHealthMonitor::new());
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let pool = CircuitPool::new(config, health_monitor, builder);
        pool.initialize().await.unwrap();

        // Pool is empty, but acquire should build on demand
        let circuit_id = pool.acquire_circuit().await.unwrap();
        assert!(circuit_id > 0);
    }

    #[test]
    fn test_pool_statistics() {
        let stats = PoolStatistics {
            total_circuits: 10,
            building_circuits: 2,
            ready_circuits: 5,
            in_use_circuits: 2,
            retiring_circuits: 1,
            available_in_queue: 5,
            total_bytes_transferred: 1024000,
            total_circuit_uses: 100,
        };

        assert_eq!(stats.total_circuits, 10);
        assert_eq!(stats.total_bytes_transferred, 1024000);
    }
}
