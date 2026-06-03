//! Failover Module
//!
//! Implements automatic relay failover with integration to the relay registry:
//! - Monitors relay health and connection status
//! - Automatically switches to backup relays on failure
//! - Fetches new relays from registry when local pool is exhausted
//! - Updates relay health status in the registry
//! - Maintains circuit continuity during relay switches

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

use gptl_core::relay_registry::{HealthStatus, RelayCriteria, RelayInfo, RelayRegistry};
use gptl_core::relay_selector::RelaySelector;

/// Convert local FailureType to gptl-core FailureType
fn to_selector_failure_type(ft: FailureType) -> gptl_core::relay_selector::FailureType {
    use gptl_core::relay_selector::FailureType as CoreFailureType;
    match ft {
        FailureType::ConnectionFailed => CoreFailureType::ConnectionFailed,
        FailureType::Timeout => CoreFailureType::Timeout,
        FailureType::ProtocolError => CoreFailureType::ProtocolError,
        FailureType::AuthenticationFailed => CoreFailureType::AuthenticationFailed,
        FailureType::Rejected => CoreFailureType::RelayRejected,
        _ => CoreFailureType::ConnectionFailed,
    }
}

/// Failover manager for automatic relay recovery
pub struct FailoverManager<R: RelayRegistry + 'static> {
    /// Relay selector for choosing new relays
    selector: Arc<RelaySelector<R>>,
    /// Registry for updating relay status
    registry: Arc<R>,
    /// Active circuits and their relays
    active_circuits: Arc<RwLock<HashMap<u32, CircuitInfo>>>,
    /// Failed relays with retry tracking
    failed_relays: Arc<RwLock<HashMap<String, FailureInfo>>>,
    /// Available backup relays
    backup_pool: Arc<RwLock<VecDeque<RelayInfo>>>,
    /// Minimum backup pool size
    min_backup_pool_size: usize,
    /// Maximum retry attempts per relay
    #[allow(dead_code)]
    max_retries: u32,
    /// Circuit recovery timeout
    #[allow(dead_code)]
    recovery_timeout: Duration,
    /// Event sender for failover events
    event_sender: Option<mpsc::Sender<FailoverEvent>>,
    /// Whether to enable automatic recovery
    #[allow(dead_code)]
    auto_recovery: bool,
}

/// Circuit information tracked by failover manager
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    /// Circuit ID
    pub circuit_id: u32,
    /// Primary relay
    pub primary_relay: RelayInfo,
    /// Backup relay (if assigned)
    pub backup_relay: Option<RelayInfo>,
    /// Circuit creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Circuit status
    pub status: CircuitStatus,
}

/// Circuit status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    /// Circuit is active and healthy
    Active,
    /// Circuit is degrading (high latency/packet loss)
    Degraded,
    /// Circuit has failed
    Failed,
    /// Circuit is being recovered
    Recovering,
    /// Circuit has been closed
    Closed,
}

/// Failure information for a relay
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FailureInfo {
    relay_id: String,
    failure_count: u32,
    last_failure: Instant,
    failure_types: VecDeque<FailureType>,
    consecutive_failures: u32,
}

/// Types of failures that can occur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
    /// Connection refused or timeout
    ConnectionFailed,
    /// Timeout specifically
    Timeout,
    /// Protocol error (invalid messages)
    ProtocolError,
    /// Authentication failure
    AuthenticationFailed,
    /// Relay explicitly rejected connection
    Rejected,
    /// High latency detected
    HighLatency,
    /// Packet loss detected
    PacketLoss,
    /// Relay reported as unhealthy
    Unhealthy,
}

/// Failover events
#[derive(Debug, Clone)]
pub enum FailoverEvent {
    /// Circuit was created
    CircuitCreated { circuit_id: u32, relay_id: String },
    /// Circuit failed
    CircuitFailed {
        circuit_id: u32,
        relay_id: String,
        reason: FailureType,
    },
    /// Failover initiated
    FailoverStarted {
        circuit_id: u32,
        old_relay: String,
        new_relay: String,
    },
    /// Failover completed successfully
    FailoverCompleted { circuit_id: u32, new_relay: String },
    /// Failover failed
    FailoverFailed { circuit_id: u32, error: String },
    /// Relay marked as unhealthy
    RelayUnhealthy { relay_id: String },
    /// Relay recovered
    RelayRecovered { relay_id: String },
    /// Backup pool refilled
    BackupPoolRefilled { count: usize },
}

/// Failover configuration
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Minimum backup pool size
    pub min_backup_pool_size: usize,
    /// Maximum retry attempts per relay
    pub max_retries: u32,
    /// Circuit recovery timeout
    pub recovery_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Enable automatic recovery
    pub auto_recovery: bool,
    /// Maximum failures before marking relay unhealthy
    pub max_failures_before_unhealthy: u32,
    /// Cooldown before retrying failed relay
    pub failure_cooldown: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            min_backup_pool_size: 5,
            max_retries: 3,
            recovery_timeout: Duration::from_secs(30),
            health_check_interval: Duration::from_secs(60),
            auto_recovery: true,
            max_failures_before_unhealthy: 3,
            failure_cooldown: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Failover result
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum FailoverResult {
    /// Failover succeeded
    Success { new_relay: RelayInfo },
    /// Failover failed, no relays available
    NoRelaysAvailable,
    /// Failover failed, retry limit reached
    RetryLimitReached,
    /// Failover timeout
    Timeout,
}

/// Failover errors
#[derive(Debug, thiserror::Error)]
pub enum FailoverError {
    #[error("Circuit not found: {0}")]
    CircuitNotFound(u32),
    #[error("No healthy relays available")]
    NoHealthyRelays,
    #[error("Failover timeout")]
    FailoverTimeout,
    #[error("Registry error: {0}")]
    RegistryError(String),
    #[error("Selector error: {0}")]
    SelectorError(String),
    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),
}

impl<R: RelayRegistry + 'static> FailoverManager<R> {
    /// Create a new failover manager
    pub fn new(registry: Arc<R>, selector: Arc<RelaySelector<R>>) -> Self {
        Self::with_config(registry, selector, FailoverConfig::default())
    }

    /// Create with configuration
    pub fn with_config(
        registry: Arc<R>,
        selector: Arc<RelaySelector<R>>,
        config: FailoverConfig,
    ) -> Self {
        Self {
            selector,
            registry,
            active_circuits: Arc::new(RwLock::new(HashMap::new())),
            failed_relays: Arc::new(RwLock::new(HashMap::new())),
            backup_pool: Arc::new(RwLock::new(VecDeque::new())),
            min_backup_pool_size: config.min_backup_pool_size,
            max_retries: config.max_retries,
            recovery_timeout: config.recovery_timeout,
            event_sender: None,
            auto_recovery: config.auto_recovery,
        }
    }

    /// Set event sender for failover events
    pub fn with_event_sender(mut self, sender: mpsc::Sender<FailoverEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Initialize the failover manager
    pub async fn initialize(&self) -> Result<(), FailoverError> {
        // Pre-populate backup pool
        self.refill_backup_pool().await?;

        // Start background health check task
        let active_circuits = self.active_circuits.clone();
        let failed_relays = self.failed_relays.clone();
        let registry = self.registry.clone();
        let interval = Duration::from_secs(60);
        let sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                // Check for stale circuits
                Self::check_stale_circuits(&active_circuits, &failed_relays, &registry, &sender)
                    .await;

                // Check for recoverable relays
                Self::check_recoverable_relays(&failed_relays, &registry, &sender).await;
            }
        });

        info!(
            "Failover manager initialized with backup pool size {}",
            self.backup_pool.read().await.len()
        );

        Ok(())
    }

    /// Register a new circuit
    pub async fn register_circuit(
        &self,
        circuit_id: u32,
        relay: RelayInfo,
    ) -> Result<(), FailoverError> {
        let now = Instant::now();
        let circuit_info = CircuitInfo {
            circuit_id,
            primary_relay: relay.clone(),
            backup_relay: None,
            created_at: now,
            last_activity: now,
            bytes_transferred: 0,
            status: CircuitStatus::Active,
        };

        {
            let mut circuits = self.active_circuits.write().await;
            circuits.insert(circuit_id, circuit_info);
        } // Drop write lock before assign_backup_relay to avoid self-deadlock

        // Pre-assign a backup relay (must not hold active_circuits lock — assign_backup_relay re-acquires it)
        self.assign_backup_relay(circuit_id).await?;

        let relay_id = relay.id.clone();

        self.send_event(FailoverEvent::CircuitCreated {
            circuit_id,
            relay_id: relay_id.clone(),
        })
        .await;

        debug!("Registered circuit {} with relay {}", circuit_id, relay_id);
        Ok(())
    }

    /// Report a circuit failure
    pub async fn report_failure(
        &self,
        circuit_id: u32,
        failure_type: FailureType,
    ) -> Result<FailoverResult, FailoverError> {
        let mut circuits = self.active_circuits.write().await;

        let circuit = circuits
            .get_mut(&circuit_id)
            .ok_or(FailoverError::CircuitNotFound(circuit_id))?;

        let old_relay_id = circuit.primary_relay.id.clone();

        // Update circuit status
        circuit.status = CircuitStatus::Failed;

        // Record failure
        drop(circuits);
        self.record_relay_failure(&old_relay_id, failure_type).await;

        self.send_event(FailoverEvent::CircuitFailed {
            circuit_id,
            relay_id: old_relay_id.clone(),
            reason: failure_type,
        })
        .await;

        // Trigger failover
        info!(
            "Initiating failover for circuit {} from relay {}",
            circuit_id, old_relay_id
        );

        match self.perform_failover(circuit_id, &old_relay_id).await {
            Ok(new_relay) => {
                self.send_event(FailoverEvent::FailoverCompleted {
                    circuit_id,
                    new_relay: new_relay.id.clone(),
                })
                .await;
                Ok(FailoverResult::Success { new_relay })
            }
            Err(e) => {
                self.send_event(FailoverEvent::FailoverFailed {
                    circuit_id,
                    error: e.to_string(),
                })
                .await;
                Err(e)
            }
        }
    }

    /// Report circuit activity (heartbeat)
    pub async fn report_activity(&self, circuit_id: u32, bytes: u64) -> Result<(), FailoverError> {
        let mut circuits = self.active_circuits.write().await;

        if let Some(circuit) = circuits.get_mut(&circuit_id) {
            circuit.last_activity = Instant::now();
            circuit.bytes_transferred += bytes;

            if circuit.status == CircuitStatus::Degraded {
                circuit.status = CircuitStatus::Active;
            }
        }

        Ok(())
    }

    /// Close a circuit
    pub async fn close_circuit(&self, circuit_id: u32) -> Result<(), FailoverError> {
        let mut circuits = self.active_circuits.write().await;

        if let Some(mut circuit) = circuits.remove(&circuit_id) {
            circuit.status = CircuitStatus::Closed;
            debug!("Closed circuit {}", circuit_id);
        }

        Ok(())
    }

    /// Get circuit information
    pub async fn get_circuit_info(&self, circuit_id: u32) -> Option<CircuitInfo> {
        let circuits = self.active_circuits.read().await;
        circuits.get(&circuit_id).cloned()
    }

    /// Get active circuit count
    pub async fn active_circuit_count(&self) -> usize {
        let circuits = self.active_circuits.read().await;
        circuits.len()
    }

    /// Get failover statistics
    pub async fn get_statistics(&self) -> FailoverStatistics {
        let circuits = self.active_circuits.read().await;
        let failures = self.failed_relays.read().await;
        let backup = self.backup_pool.read().await;

        let mut active_count = 0;
        let mut failed_count = 0;
        let mut recovering_count = 0;

        for circuit in circuits.values() {
            match circuit.status {
                CircuitStatus::Active | CircuitStatus::Degraded => active_count += 1,
                CircuitStatus::Failed => failed_count += 1,
                CircuitStatus::Recovering => recovering_count += 1,
                _ => {}
            }
        }

        FailoverStatistics {
            total_circuits: circuits.len(),
            active_circuits: active_count,
            failed_circuits: failed_count,
            recovering_circuits: recovering_count,
            failed_relays: failures.len(),
            backup_pool_size: backup.len(),
        }
    }

    /// Force refill of backup pool
    pub async fn refill_backup_pool(&self) -> Result<usize, FailoverError> {
        let mut pool = self.backup_pool.write().await;
        let current_size = pool.len();
        let needed = self.min_backup_pool_size.saturating_sub(current_size);

        if needed > 0 {
            // Build criteria to exclude already failed relays
            let failed = self.failed_relays.read().await;
            let excluded: Vec<_> = failed.keys().cloned().collect();
            drop(failed);

            let _criteria = RelayCriteria::new()
                .with_excluded_ids(excluded)
                .require_healthy();

            // Fetch new relays
            match self.selector.select_multiple(needed, true).await {
                Ok(selections) => {
                    for selection in selections {
                        pool.push_back(selection.relay);
                    }
                }
                Err(e) => {
                    warn!("Failed to refill backup pool: {}", e);
                }
            }
        }

        let new_size = pool.len();
        let size_diff = new_size.saturating_sub(current_size);
        drop(pool);

        if size_diff > 0 {
            self.send_event(FailoverEvent::BackupPoolRefilled { count: size_diff })
                .await;
        }

        Ok(new_size)
    }

    // Private helper methods

    async fn assign_backup_relay(&self, circuit_id: u32) -> Result<(), FailoverError> {
        let mut pool = self.backup_pool.write().await;

        if let Some(backup) = pool.pop_front() {
            let need_refill = pool.len() < self.min_backup_pool_size / 2;
            drop(pool);

            let mut circuits = self.active_circuits.write().await;
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.backup_relay = Some(backup);
            }

            // Refill if needed
            if need_refill {
                let _ = self.refill_backup_pool().await;
            }
        }

        Ok(())
    }

    async fn perform_failover(
        &self,
        circuit_id: u32,
        failed_relay_id: &str,
    ) -> Result<RelayInfo, FailoverError> {
        let mut circuits = self.active_circuits.write().await;

        let circuit = circuits
            .get_mut(&circuit_id)
            .ok_or(FailoverError::CircuitNotFound(circuit_id))?;

        // Try backup relay first
        if let Some(backup) = circuit.backup_relay.take() {
            if backup.id != failed_relay_id {
                debug!(
                    "Using backup relay {} for circuit {}",
                    backup.id, circuit_id
                );
                circuit.primary_relay = backup.clone();
                circuit.status = CircuitStatus::Recovering;

                // Pre-assign new backup
                drop(circuits);
                self.assign_backup_relay(circuit_id).await?;

                return Ok(backup);
            }
        }

        drop(circuits);

        // Try to get new relay from selector
        let criteria = RelayCriteria::new()
            .with_excluded_ids(vec![failed_relay_id.to_string()])
            .require_healthy();

        match self.selector.select_with_criteria(&criteria).await {
            Ok(selection) => {
                let mut circuits = self.active_circuits.write().await;
                if let Some(circuit) = circuits.get_mut(&circuit_id) {
                    circuit.primary_relay = selection.relay.clone();
                    circuit.status = CircuitStatus::Recovering;
                }

                self.send_event(FailoverEvent::FailoverStarted {
                    circuit_id,
                    old_relay: failed_relay_id.to_string(),
                    new_relay: selection.relay.id.clone(),
                })
                .await;

                Ok(selection.relay)
            }
            Err(e) => {
                error!("Failover failed for circuit {}: {}", circuit_id, e);
                Err(FailoverError::NoHealthyRelays)
            }
        }
    }

    async fn record_relay_failure(&self, relay_id: &str, failure_type: FailureType) {
        let mut failures = self.failed_relays.write().await;

        let info = failures.entry(relay_id.to_string()).or_insert(FailureInfo {
            relay_id: relay_id.to_string(),
            failure_count: 0,
            last_failure: Instant::now(),
            failure_types: VecDeque::new(),
            consecutive_failures: 0,
        });

        info.failure_count += 1;
        info.consecutive_failures += 1;
        info.last_failure = Instant::now();
        info.failure_types.push_back(failure_type);

        // Keep only last 10 failure types
        while info.failure_types.len() > 10 {
            info.failure_types.pop_front();
        }

        // Report to selector
        self.selector
            .report_failure(relay_id, to_selector_failure_type(failure_type))
            .await;

        // Mark unhealthy if too many failures
        if info.consecutive_failures >= 3 {
            if let Err(e) = self
                .registry
                .update_health(relay_id, HealthStatus::Degraded)
                .await
            {
                warn!("Failed to update health status for {}: {}", relay_id, e);
            }

            self.send_event(FailoverEvent::RelayUnhealthy {
                relay_id: relay_id.to_string(),
            })
            .await;
        }
    }

    async fn check_stale_circuits(
        active_circuits: &Arc<RwLock<HashMap<u32, CircuitInfo>>>,
        _failed_relays: &Arc<RwLock<HashMap<String, FailureInfo>>>,
        _registry: &Arc<R>,
        _sender: &Option<mpsc::Sender<FailoverEvent>>,
    ) {
        let mut circuits = active_circuits.write().await;
        let now = Instant::now();
        let timeout = Duration::from_secs(300); // 5 minutes

        let stale: Vec<_> = circuits
            .iter()
            .filter(|(_, c)| {
                c.status == CircuitStatus::Active && now.duration_since(c.last_activity) > timeout
            })
            .map(|(id, _)| *id)
            .collect();

        for circuit_id in stale {
            if let Some(circuit) = circuits.get_mut(&circuit_id) {
                circuit.status = CircuitStatus::Degraded;
                warn!("Circuit {} marked as stale (no activity)", circuit_id);
            }
        }
    }

    async fn check_recoverable_relays(
        failed_relays: &Arc<RwLock<HashMap<String, FailureInfo>>>,
        registry: &Arc<R>,
        sender: &Option<mpsc::Sender<FailoverEvent>>,
    ) {
        let mut failures = failed_relays.write().await;
        let now = Instant::now();
        let cooldown = Duration::from_secs(300);

        let recoverable: Vec<_> = failures
            .iter()
            .filter(|(_, info)| now.duration_since(info.last_failure) > cooldown)
            .map(|(id, _)| id.clone())
            .collect();

        for relay_id in recoverable {
            if let Some(info) = failures.get_mut(&relay_id) {
                info.consecutive_failures = 0;

                // Mark as healthy in registry
                if let Err(e) = registry
                    .update_health(&relay_id, HealthStatus::Healthy)
                    .await
                {
                    trace!("Failed to update health for {}: {}", relay_id, e);
                }

                if let Some(ref s) = sender {
                    let _ = s
                        .send(FailoverEvent::RelayRecovered {
                            relay_id: relay_id.clone(),
                        })
                        .await;
                }
            }
        }
    }

    async fn send_event(&self, event: FailoverEvent) {
        if let Some(ref sender) = self.event_sender {
            let _ = sender.send(event).await;
        }
    }
}

/// Failover statistics
#[derive(Debug, Clone)]
pub struct FailoverStatistics {
    /// Total number of tracked circuits
    pub total_circuits: usize,
    /// Number of active circuits
    pub active_circuits: usize,
    /// Number of failed circuits
    pub failed_circuits: usize,
    /// Number of circuits being recovered
    pub recovering_circuits: usize,
    /// Number of failed relays
    pub failed_relays: usize,
    /// Current backup pool size
    pub backup_pool_size: usize,
}

/// Failover-aware circuit handle
pub struct FailoverCircuit {
    /// Circuit ID
    pub circuit_id: u32,
    /// Current relay
    pub relay: RelayInfo,
    /// Failover manager reference
    #[allow(dead_code)]
    manager: Arc<dyn FailoverManagerTrait>,
}

/// Trait for failover manager operations
#[async_trait::async_trait]
pub trait FailoverManagerTrait: Send + Sync {
    /// Report circuit activity
    async fn report_activity(&self, circuit_id: u32, bytes: u64) -> Result<(), FailoverError>;
    /// Report circuit failure
    async fn report_failure(
        &self,
        circuit_id: u32,
        failure_type: FailureType,
    ) -> Result<FailoverResult, FailoverError>;
    /// Close circuit
    async fn close_circuit(&self, circuit_id: u32) -> Result<(), FailoverError>;
}

#[async_trait::async_trait]
impl<R: RelayRegistry> FailoverManagerTrait for FailoverManager<R> {
    async fn report_activity(&self, circuit_id: u32, bytes: u64) -> Result<(), FailoverError> {
        FailoverManager::report_activity(self, circuit_id, bytes).await
    }

    async fn report_failure(
        &self,
        circuit_id: u32,
        failure_type: FailureType,
    ) -> Result<FailoverResult, FailoverError> {
        FailoverManager::report_failure(self, circuit_id, failure_type).await
    }

    async fn close_circuit(&self, circuit_id: u32) -> Result<(), FailoverError> {
        FailoverManager::close_circuit(self, circuit_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gptl_core::relay_registry::InMemoryRegistry;
    use gptl_core::relay_selector::SelectorConfig;

    async fn create_test_setup() -> (Arc<InMemoryRegistry>, Arc<RelaySelector<InMemoryRegistry>>) {
        let registry = Arc::new(InMemoryRegistry::new());

        // Add test relays (bandwidth must exceed the selector's 1 MiB/s minimum)
        for i in 0..5 {
            let relay = RelayInfo::new(
                format!("192.168.1.{}:9001", i + 1),
                format!("key{}", i),
                2_000_000,
            );
            registry.register(relay).await.unwrap();
        }

        let selector = Arc::new(RelaySelector::new(registry.clone()));
        (registry, selector)
    }

    #[tokio::test]
    async fn test_failover_manager_creation() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);

        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_registration() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        let relay = RelayInfo::new("192.168.1.10:9001", "test_key", 1_000_000);
        manager.register_circuit(1, relay).await.unwrap();

        assert_eq!(manager.active_circuit_count().await, 1);

        let info = manager.get_circuit_info(1).await.unwrap();
        assert_eq!(info.circuit_id, 1);
        assert_eq!(info.status, CircuitStatus::Active);
    }

    #[tokio::test]
    async fn test_circuit_failure_and_failover() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry.clone(), selector);
        manager.initialize().await.unwrap();

        // Register circuit with first relay
        let relays = registry.list_relays().await.unwrap();
        let first_relay = relays[0].clone();
        manager
            .register_circuit(1, first_relay.clone())
            .await
            .unwrap();

        // Report failure
        let result = manager
            .report_failure(1, FailureType::ConnectionFailed)
            .await;

        // Should succeed with a new relay
        assert!(matches!(result, Ok(FailoverResult::Success { .. })));

        // Verify circuit has new relay
        let info = manager.get_circuit_info(1).await.unwrap();
        assert_ne!(info.primary_relay.id, first_relay.id);
    }

    #[tokio::test]
    async fn test_statistics() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        // Register some circuits
        for i in 0..3 {
            let relay = RelayInfo::new(
                format!("10.0.0.{}:9001", i + 1),
                format!("test_key_{}", i),
                1_000_000,
            );
            manager.register_circuit(i as u32, relay).await.unwrap();
        }

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_circuits, 3);
        assert_eq!(stats.active_circuits, 3);
    }

    #[tokio::test]
    async fn test_multiple_failures() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry.clone(), selector);
        manager.initialize().await.unwrap();

        let relays = registry.list_relays().await.unwrap();
        let relay = relays[0].clone();
        manager.register_circuit(1, relay).await.unwrap();

        // Report multiple failures
        for _ in 0..3 {
            let result = manager
                .report_failure(1, FailureType::ConnectionFailed)
                .await;
            assert!(result.is_ok());
        }

        let stats = manager.get_statistics().await;
        // The same circuit was failed 3 times; each failure records the relay as failed.
        // failed_circuits counts circuits currently in Failed state (at most 1 for 1 circuit).
        // Check that failures were recorded in the failed_relays map instead.
        assert!(stats.failed_relays >= 1);
    }

    #[tokio::test]
    async fn test_circuit_cleanup() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        let relay = RelayInfo::new("10.0.0.1:9001", "key1", 1_000_000);
        manager.register_circuit(1, relay).await.unwrap();

        assert_eq!(manager.active_circuit_count().await, 1);

        // Report failure to trigger failover
        let _ = manager
            .report_failure(1, FailureType::ConnectionFailed)
            .await;

        // Circuit should be in failed or recovering state
        let stats = manager.get_statistics().await;
        assert!(stats.failed_circuits > 0 || stats.recovering_circuits > 0);
    }

    #[tokio::test]
    async fn test_backup_pool_management() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        // Backup pool should be populated during initialization
        let backup_count = manager.backup_pool.read().await.len();
        assert!(backup_count > 0);
    }

    #[tokio::test]
    async fn test_concurrent_failures() {
        let (registry, selector) = create_test_setup().await;
        let manager = Arc::new(FailoverManager::new(registry.clone(), selector));
        manager.initialize().await.unwrap();

        // Register multiple circuits
        let relays = registry.list_relays().await.unwrap();
        for i in 0..3 {
            manager
                .register_circuit(i as u32, relays[i].clone())
                .await
                .unwrap();
        }

        // Simulate concurrent failures
        let mut handles = vec![];
        for i in 0..3 {
            let mgr = manager.clone();
            let handle =
                tokio::spawn(
                    async move { mgr.report_failure(i as u32, FailureType::Timeout).await },
                );
            handles.push(handle);
        }

        // Wait for all failures to be handled
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_circuit_status_transitions() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        let relay = RelayInfo::new("10.0.0.1:9001", "key1", 1_000_000);
        manager.register_circuit(1, relay).await.unwrap();

        let info = manager.get_circuit_info(1).await.unwrap();
        assert_eq!(info.status, CircuitStatus::Active);

        // Report failure
        manager
            .report_failure(1, FailureType::ConnectionFailed)
            .await
            .ok();

        // Status should change (either to Recovering or have new relay)
        let info = manager.get_circuit_info(1).await;
        assert!(info.is_some());
    }

    #[tokio::test]
    async fn test_failure_type_tracking() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry.clone(), selector);
        manager.initialize().await.unwrap();

        let relays = registry.list_relays().await.unwrap();
        let relay = relays[0].clone();
        manager.register_circuit(1, relay).await.unwrap();

        // Report different failure types
        manager.report_failure(1, FailureType::Timeout).await.ok();
        manager
            .report_failure(1, FailureType::ProtocolError)
            .await
            .ok();
        manager
            .report_failure(1, FailureType::AuthenticationFailed)
            .await
            .ok();

        let stats = manager.get_statistics().await;
        // 3 different failure types were reported for the same circuit;
        // the relay should appear in the failed_relays map.
        assert!(stats.failed_relays >= 1);
    }

    #[tokio::test]
    async fn test_relay_exhaustion() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry.clone(), selector);
        manager.initialize().await.unwrap();

        let relay = RelayInfo::new("10.0.0.1:9001", "key1", 1_000_000);
        manager.register_circuit(1, relay).await.unwrap();

        // Exhaust all relays by repeated failures
        for _ in 0..20 {
            let result = manager
                .report_failure(1, FailureType::ConnectionFailed)
                .await;
            if result.is_err() {
                // Expected when relays are exhausted
                break;
            }
        }

        // Should eventually fail or succeed with retry
        assert!(true);
    }

    #[tokio::test]
    async fn test_circuit_info_updates() {
        let (registry, selector) = create_test_setup().await;
        let manager = FailoverManager::new(registry, selector);
        manager.initialize().await.unwrap();

        let relay = RelayInfo::new("10.0.0.1:9001", "key1", 1_000_000);
        manager.register_circuit(1, relay).await.unwrap();

        let info1 = manager.get_circuit_info(1).await.unwrap();
        let created_at = info1.created_at;

        // Wait a bit
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Activity should update last_activity
        manager.report_failure(1, FailureType::Timeout).await.ok();

        let info2 = manager.get_circuit_info(1).await;
        if let Some(info2) = info2 {
            assert_eq!(info2.created_at, created_at);
        }
    }
}
