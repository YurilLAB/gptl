//! Circuit Manager Module
//!
//! Central manager for all circuit operations, coordinating:
//! - Circuit pool management
//! - Health monitoring
//! - Circuit rotation
//! - Integration with failover system

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

use super::health::{
    CircuitHealthMonitor, FailureType, HealthMonitorConfig, HealthStatistics, HealthStatus,
};
use super::pool::{CircuitId, CircuitPool, CircuitPoolConfig, PoolStatistics, RetireReason};
use super::rotation::{RotationPolicy, RotationStatistics, RotationTrigger};

/// Circuit manager configuration
#[derive(Debug, Clone)]
pub struct CircuitManagerConfig {
    /// Pool configuration
    pub pool_config: CircuitPoolConfig,
    /// Health monitor configuration
    pub health_config: HealthMonitorConfig,
    /// Rotation policy
    pub rotation_policy: RotationPolicy,
    /// Maximum concurrent circuits
    pub max_concurrent_circuits: usize,
    /// Circuit timeout
    pub circuit_timeout: Duration,
    /// Enable automatic rotation
    pub enable_rotation: bool,
    /// Enable health monitoring
    pub enable_health_monitoring: bool,
    /// Enable pool management
    pub enable_pool_management: bool,
}

impl Default for CircuitManagerConfig {
    fn default() -> Self {
        Self {
            pool_config: CircuitPoolConfig::default(),
            health_config: HealthMonitorConfig::default(),
            rotation_policy: RotationPolicy::default(),
            max_concurrent_circuits: 100,
            circuit_timeout: Duration::from_secs(60),
            enable_rotation: true,
            enable_health_monitoring: true,
            enable_pool_management: true,
        }
    }
}

/// Circuit handle for users
#[derive(Debug, Clone)]
pub struct CircuitHandle {
    /// Circuit ID
    pub id: CircuitId,
    /// Circuit path (relay IDs)
    pub path: Vec<String>,
    /// Creation time
    pub created_at: Instant,
    /// Health score (0-100)
    pub health_score: u8,
}

/// Active circuit information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ActiveCircuit {
    /// Circuit ID
    id: CircuitId,
    /// Associated stream IDs
    streams: Vec<u64>,
    /// Creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Total bytes transferred
    bytes_transferred: u64,
    /// Total requests made
    request_count: u64,
    /// Circuit path
    path: Vec<String>,
    /// Whether circuit is closing
    is_closing: bool,
}

/// Circuit manager events
#[derive(Debug, Clone)]
pub enum CircuitManagerEvent {
    /// Circuit created and ready
    CircuitReady { circuit_id: CircuitId },
    /// Circuit acquired for use
    CircuitAcquired {
        circuit_id: CircuitId,
        purpose: String,
    },
    /// Circuit released
    CircuitReleased { circuit_id: CircuitId },
    /// Circuit closed
    CircuitClosed {
        circuit_id: CircuitId,
        reason: String,
    },
    /// Circuit rotated
    CircuitRotated {
        old_id: CircuitId,
        new_id: CircuitId,
        trigger: RotationTrigger,
    },
    /// Health status changed
    HealthStatusChanged {
        circuit_id: CircuitId,
        new_status: HealthStatus,
    },
    /// Pool refilled
    PoolRefilled { count: usize },
    /// All circuits failed
    AllCircuitsFailed,
    /// Circuit manager error
    Error { error: String },
}

/// Circuit manager statistics
#[derive(Debug, Clone)]
pub struct CircuitManagerStatistics {
    /// Pool statistics
    pub pool_stats: PoolStatistics,
    /// Health statistics
    pub health_stats: HealthStatistics,
    /// Rotation statistics
    pub rotation_stats: Option<RotationStatistics>,
    /// Number of active streams
    pub active_streams: usize,
    /// Total circuits created
    pub total_circuits_created: u64,
    /// Total circuits destroyed
    pub total_circuits_destroyed: u64,
    /// Average circuit lifetime
    pub average_circuit_lifetime: Duration,
}

/// Main circuit manager
pub struct CircuitManager<B: super::pool::CircuitBuilder + 'static> {
    /// Configuration
    config: CircuitManagerConfig,
    /// Health monitor
    health_monitor: Arc<CircuitHealthMonitor>,
    /// Circuit pool
    pool: Arc<CircuitPool>,
    /// Active circuits
    active_circuits: Arc<RwLock<HashMap<CircuitId, ActiveCircuit>>>,
    /// Next stream ID
    #[allow(dead_code)]
    next_stream_id: Arc<RwLock<u64>>,
    /// Event sender
    event_sender: Option<mpsc::Sender<CircuitManagerEvent>>,
    /// Circuit builder
    #[allow(dead_code)]
    builder: Arc<B>,
    /// Total circuits created counter
    total_created: Arc<RwLock<u64>>,
    /// Total circuits destroyed counter
    total_destroyed: Arc<RwLock<u64>>,
    /// Manager start time
    start_time: Instant,
}

impl<B: super::pool::CircuitBuilder> CircuitManager<B> {
    /// Create a new circuit manager
    pub fn new(config: CircuitManagerConfig, builder: Arc<B>) -> Self {
        let health_monitor = Arc::new(CircuitHealthMonitor::with_config(
            config.health_config.clone(),
        ));

        let pool = Arc::new(CircuitPool::new(
            config.pool_config.clone(),
            health_monitor.clone(),
            builder.clone(),
        ));

        Self {
            config,
            health_monitor,
            pool,
            active_circuits: Arc::new(RwLock::new(HashMap::new())),
            next_stream_id: Arc::new(RwLock::new(1)),
            event_sender: None,
            builder,
            total_created: Arc::new(RwLock::new(0)),
            total_destroyed: Arc::new(RwLock::new(0)),
            start_time: Instant::now(),
        }
    }

    /// Set event sender
    pub fn with_event_sender(mut self, sender: mpsc::Sender<CircuitManagerEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Initialize the circuit manager
    pub async fn initialize(&self) -> Result<(), CircuitManagerError> {
        info!("Initializing circuit manager");

        // Start health monitoring
        if self.config.enable_health_monitoring {
            self.health_monitor.start_health_check_task();
            info!("Health monitoring started");
        }

        // Initialize pool
        if self.config.enable_pool_management {
            self.pool
                .initialize()
                .await
                .map_err(|e| CircuitManagerError::PoolInitializationFailed(e.to_string()))?;
            info!("Circuit pool initialized");
        }

        // Start background tasks
        self.start_background_tasks();

        info!("Circuit manager initialized successfully");
        Ok(())
    }

    /// Acquire a circuit for use
    pub async fn acquire_circuit(
        &self,
        purpose: &str,
        destination: Option<IpAddr>,
    ) -> Result<CircuitHandle, CircuitManagerError> {
        trace!(purpose, ?destination, "Acquiring circuit");

        // Try to get a circuit from the pool
        let circuit_id = self
            .pool
            .acquire_circuit()
            .await
            .map_err(|e| CircuitManagerError::NoCircuitAvailable(e.to_string()))?;

        // Get circuit info
        let pool_circuit = self
            .pool
            .get_circuit(circuit_id)
            .await
            .ok_or(CircuitManagerError::CircuitNotFound(circuit_id))?;

        // Get health score
        let health_score = self
            .health_monitor
            .get_health_score(circuit_id)
            .await
            .unwrap_or(100);

        // Register as active
        {
            let mut active = self.active_circuits.write().await;
            active.insert(
                circuit_id,
                ActiveCircuit {
                    id: circuit_id,
                    streams: Vec::new(),
                    created_at: Instant::now(),
                    last_activity: Instant::now(),
                    bytes_transferred: 0,
                    request_count: 0,
                    path: pool_circuit.path.clone(),
                    is_closing: false,
                },
            );
        }

        // Update counters
        {
            let mut created = self.total_created.write().await;
            *created += 1;
        }

        self.send_event(CircuitManagerEvent::CircuitAcquired {
            circuit_id,
            purpose: purpose.to_string(),
        })
        .await;

        debug!(circuit_id, purpose, "Circuit acquired");

        Ok(CircuitHandle {
            id: circuit_id,
            path: pool_circuit.path,
            created_at: pool_circuit.created_at,
            health_score,
        })
    }

    /// Release a circuit back to the manager
    pub async fn release_circuit(&self, circuit_id: CircuitId) -> Result<(), CircuitManagerError> {
        debug!(circuit_id, "Releasing circuit");

        // Remove from active
        {
            let mut active = self.active_circuits.write().await;
            active.remove(&circuit_id);
        }

        // Return to pool
        self.pool
            .release_circuit(circuit_id)
            .await
            .map_err(|e| CircuitManagerError::PoolError(e.to_string()))?;

        self.send_event(CircuitManagerEvent::CircuitReleased { circuit_id })
            .await;

        Ok(())
    }

    /// Report successful circuit usage
    pub async fn report_success(
        &self,
        circuit_id: CircuitId,
        latency: Duration,
        bytes: u64,
    ) -> Result<(), CircuitManagerError> {
        // Update health monitor
        self.health_monitor
            .record_success(circuit_id, latency, bytes)
            .await;

        // Update active circuit stats
        {
            let mut active = self.active_circuits.write().await;
            if let Some(circuit) = active.get_mut(&circuit_id) {
                circuit.last_activity = Instant::now();
                circuit.bytes_transferred += bytes;
                circuit.request_count += 1;
            }
        }

        // Update pool stats
        self.pool
            .update_circuit_usage(circuit_id, bytes)
            .await
            .map_err(|e| CircuitManagerError::PoolError(e.to_string()))?;

        Ok(())
    }

    /// Report circuit failure
    pub async fn report_failure(
        &self,
        circuit_id: CircuitId,
        failure_type: FailureType,
    ) -> Result<(), CircuitManagerError> {
        warn!(circuit_id, ?failure_type, "Circuit failure reported");

        // Update health monitor
        self.health_monitor
            .record_failure(circuit_id, failure_type)
            .await;

        // Check if we need emergency rotation
        let should_emergency_rotate = {
            let active = self.active_circuits.read().await;
            active.contains_key(&circuit_id)
        };

        if should_emergency_rotate {
            // Check health status
            if let Some(status) = self.health_monitor.get_health_status(circuit_id).await {
                self.send_event(CircuitManagerEvent::HealthStatusChanged {
                    circuit_id,
                    new_status: status,
                })
                .await;

                // If failed, close the circuit
                if status == HealthStatus::Failed {
                    self.close_circuit(circuit_id, "Health check failed")
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Close a circuit
    pub async fn close_circuit(
        &self,
        circuit_id: CircuitId,
        reason: &str,
    ) -> Result<(), CircuitManagerError> {
        info!(circuit_id, reason, "Closing circuit");

        // Remove from active
        {
            let mut active = self.active_circuits.write().await;
            active.remove(&circuit_id);
        }

        // Retire from pool
        let _ = self
            .pool
            .retire_circuit(circuit_id, RetireReason::Explicit)
            .await;

        // Update counters
        {
            let mut destroyed = self.total_destroyed.write().await;
            *destroyed += 1;
        }

        self.send_event(CircuitManagerEvent::CircuitClosed {
            circuit_id,
            reason: reason.to_string(),
        })
        .await;

        Ok(())
    }

    /// Rotate a circuit
    pub async fn rotate_circuit(
        &self,
        old_circuit_id: CircuitId,
        trigger: RotationTrigger,
    ) -> Result<CircuitHandle, CircuitManagerError> {
        info!(old_circuit_id, %trigger, "Rotating circuit");

        // Acquire new circuit
        let new_handle = self.acquire_circuit("rotation", None).await?;

        // Close old circuit
        self.close_circuit(old_circuit_id, &format!("Rotated: {}", trigger))
            .await?;

        self.send_event(CircuitManagerEvent::CircuitRotated {
            old_id: old_circuit_id,
            new_id: new_handle.id,
            trigger,
        })
        .await;

        Ok(new_handle)
    }

    /// Get the healthiest available circuit
    pub async fn get_healthiest_circuit(&self, candidates: &[CircuitId]) -> Option<CircuitId> {
        self.health_monitor.get_healthiest_circuit(candidates).await
    }

    /// Get circuit statistics
    pub async fn get_statistics(&self) -> CircuitManagerStatistics {
        let pool_stats = self.pool.get_statistics().await;
        let health_stats = self.health_monitor.get_statistics().await;

        let active_count = self.active_circuits.read().await.len();
        let total_created = *self.total_created.read().await;
        let total_destroyed = *self.total_destroyed.read().await;

        let avg_lifetime = if total_destroyed > 0 {
            let elapsed = self.start_time.elapsed().as_secs();
            Duration::from_secs(elapsed / total_destroyed)
        } else {
            Duration::from_secs(0)
        };

        CircuitManagerStatistics {
            pool_stats,
            health_stats,
            rotation_stats: None, // Would need rotation component
            active_streams: active_count,
            total_circuits_created: total_created,
            total_circuits_destroyed: total_destroyed,
            average_circuit_lifetime: avg_lifetime,
        }
    }

    /// Get health status for a circuit
    pub async fn get_circuit_health(&self, circuit_id: CircuitId) -> Option<HealthStatus> {
        self.health_monitor.get_health_status(circuit_id).await
    }

    /// Get all unhealthy circuits
    pub async fn get_unhealthy_circuits(&self) -> Vec<CircuitId> {
        self.health_monitor.get_unhealthy_circuits().await
    }

    /// Check if any circuits are available
    pub async fn has_available_circuits(&self) -> bool {
        let stats = self.pool.get_statistics().await;
        stats.ready_circuits > 0 || stats.building_circuits > 0
    }

    /// Handle all circuits failed scenario
    #[allow(dead_code)]
    async fn handle_all_circuits_failed(&self) {
        error!("All circuits have failed!");

        self.send_event(CircuitManagerEvent::AllCircuitsFailed)
            .await;

        // Try to rebuild the pool
        warn!("Attempting to rebuild circuit pool");

        // Give the pool some time to recover
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    /// Start background maintenance tasks
    fn start_background_tasks(&self) {
        self.start_health_check_task();
        self.start_cleanup_task();
    }

    /// Start health check task
    fn start_health_check_task(&self) {
        let health_monitor = self.health_monitor.clone();
        let active_circuits = self.active_circuits.clone();
        let pool = self.pool.clone();
        let event_sender = self.event_sender.clone();
        let interval = self.config.health_config.health_check_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                // Get unhealthy circuits
                let unhealthy = health_monitor.get_unhealthy_circuits().await;

                for circuit_id in unhealthy {
                    // Check if active
                    let is_active = {
                        let active = active_circuits.read().await;
                        active.contains_key(&circuit_id)
                    };

                    if is_active {
                        warn!(circuit_id, "Active circuit became unhealthy, retiring");

                        // Get current status for event
                        if let Some(status) = health_monitor.get_health_status(circuit_id).await {
                            if let Some(ref sender) = event_sender {
                                let _ = sender
                                    .send(CircuitManagerEvent::HealthStatusChanged {
                                        circuit_id,
                                        new_status: status,
                                    })
                                    .await;
                            }
                        }

                        // Remove from active
                        {
                            let mut active = active_circuits.write().await;
                            active.remove(&circuit_id);
                        }

                        // Retire from pool
                        let _ = pool
                            .retire_circuit(circuit_id, RetireReason::HealthCheck)
                            .await;
                    }
                }

                trace!("Health check task cycle completed");
            }
        });
    }

    /// Start cleanup task for stale circuits
    fn start_cleanup_task(&self) {
        let active_circuits = self.active_circuits.clone();
        let pool = self.pool.clone();
        let health_monitor = self.health_monitor.clone();
        let idle_timeout = self.config.health_config.idle_timeout;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));

            loop {
                ticker.tick().await;

                let now = Instant::now();
                let mut to_remove = Vec::new();

                // Find stale circuits
                {
                    let active = active_circuits.read().await;
                    for (id, circuit) in active.iter() {
                        if now.duration_since(circuit.last_activity) > idle_timeout {
                            to_remove.push(*id);
                        }
                    }
                }

                // Remove stale circuits
                for circuit_id in to_remove {
                    warn!(circuit_id, "Removing stale circuit");

                    {
                        let mut active = active_circuits.write().await;
                        active.remove(&circuit_id);
                    }

                    let _ = pool.release_circuit(circuit_id).await;
                    health_monitor.unregister_circuit(circuit_id).await;
                }

                trace!("Cleanup task cycle completed");
            }
        });
    }

    /// Send event if sender is configured
    async fn send_event(&self, event: CircuitManagerEvent) {
        if let Some(ref sender) = self.event_sender {
            let _ = sender.send(event).await;
        }
    }
}

/// Circuit manager errors
#[derive(Debug, thiserror::Error)]
pub enum CircuitManagerError {
    #[error("Pool initialization failed: {0}")]
    PoolInitializationFailed(String),
    #[error("No circuit available: {0}")]
    NoCircuitAvailable(String),
    #[error("Circuit not found: {0}")]
    CircuitNotFound(u64),
    #[error("Pool error: {0}")]
    PoolError(String),
    #[error("Health monitor error: {0}")]
    HealthMonitorError(String),
    #[error("Rotation failed: {0}")]
    RotationFailed(String),
    #[error("All circuits failed")]
    AllCircuitsFailed,
}

#[cfg(test)]
mod tests {
    use super::super::pool::MockCircuitBuilder;
    use super::*;

    fn create_test_config() -> CircuitManagerConfig {
        CircuitManagerConfig {
            pool_config: CircuitPoolConfig {
                min_pool_size: 2,
                max_pool_size: 5,
                pre_build_count: 2,
                build_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            health_config: HealthMonitorConfig::default(),
            rotation_policy: RotationPolicy::default(),
            max_concurrent_circuits: 10,
            circuit_timeout: Duration::from_secs(30),
            enable_rotation: true,
            enable_health_monitoring: true,
            enable_pool_management: true,
        }
    }

    #[tokio::test]
    async fn test_circuit_manager_initialization() {
        let config = create_test_config();
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManager::new(config, builder);

        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_acquire_release() {
        let config = create_test_config();
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManager::new(config, builder);
        manager.initialize().await.unwrap();

        // Acquire a circuit
        let handle = manager.acquire_circuit("test", None).await.unwrap();
        assert!(handle.id > 0);
        assert_eq!(handle.health_score, 100);

        // Release it
        manager.release_circuit(handle.id).await.unwrap();

        // Check stats
        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_circuits_created, 1);
    }

    #[tokio::test]
    async fn test_circuit_health_monitoring() {
        let config = create_test_config();
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManager::new(config, builder);
        manager.initialize().await.unwrap();

        let handle = manager.acquire_circuit("test", None).await.unwrap();

        // Report success
        manager
            .report_success(handle.id, Duration::from_millis(100), 1024)
            .await
            .unwrap();

        // Check health
        let health = manager.get_circuit_health(handle.id).await;
        assert!(health.is_some());

        // Report 3 failures: score = 100 - (3*15 consecutive) - (3*10 recent) = 25 → Unhealthy
        // Using fewer than 4 to avoid HealthStatus::Failed (score=0) which auto-closes the circuit
        for _ in 0..3 {
            manager
                .report_failure(handle.id, FailureType::Timeout)
                .await
                .unwrap();
        }

        // Health should be degraded (Unhealthy, not Healthy)
        let health = manager.get_circuit_health(handle.id).await.unwrap();
        assert_ne!(health, HealthStatus::Healthy);

        manager.release_circuit(handle.id).await.unwrap();
    }

    #[tokio::test]
    async fn test_circuit_manager_statistics() {
        let config = create_test_config();
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManager::new(config, builder);
        manager.initialize().await.unwrap();

        // Create some circuits
        let handle1 = manager.acquire_circuit("test1", None).await.unwrap();
        let handle2 = manager.acquire_circuit("test2", None).await.unwrap();

        // Report activity
        manager
            .report_success(handle1.id, Duration::from_millis(100), 1000)
            .await
            .unwrap();
        manager
            .report_success(handle2.id, Duration::from_millis(200), 2000)
            .await
            .unwrap();

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_circuits_created, 2);
        assert_eq!(stats.pool_stats.in_use_circuits, 2);
        assert!(stats.health_stats.total_circuits >= 4); // At least 2 in-use + 2 pool circuits; background tasks may add more

        manager.release_circuit(handle1.id).await.unwrap();
        manager.release_circuit(handle2.id).await.unwrap();
    }

    #[tokio::test]
    async fn test_close_circuit() {
        let config = create_test_config();
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManager::new(config, builder);
        manager.initialize().await.unwrap();

        let handle = manager.acquire_circuit("test", None).await.unwrap();

        // Close the circuit
        manager
            .close_circuit(handle.id, "Test close")
            .await
            .unwrap();

        let stats = manager.get_statistics().await;
        assert_eq!(stats.total_circuits_destroyed, 1);
    }

    #[test]
    fn test_circuit_manager_config_default() {
        let config = CircuitManagerConfig::default();

        assert!(config.enable_rotation);
        assert!(config.enable_health_monitoring);
        assert!(config.enable_pool_management);
        assert_eq!(config.max_concurrent_circuits, 100);
    }

    #[test]
    fn test_circuit_handle() {
        let handle = CircuitHandle {
            id: 1,
            path: vec!["r1".to_string(), "r2".to_string()],
            created_at: Instant::now(),
            health_score: 95,
        };

        assert_eq!(handle.id, 1);
        assert_eq!(handle.path.len(), 2);
        assert_eq!(handle.health_score, 95);
    }
}
