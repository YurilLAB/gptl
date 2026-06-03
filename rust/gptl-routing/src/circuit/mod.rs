//! Circuit Management Module
//!
//! Provides comprehensive circuit management for the GPTL routing layer:
//! - Circuit pool management with pre-built ready circuits
//! - Health monitoring with EWMA-based latency tracking
//! - Automatic circuit rotation (time-based, usage-based, health-based)
//! - Integration with failover system
//!
//! Based on Tor's circuit management best practices:
//! - Exponentially Weighted Moving Average (EWMA) for latency measurement
//! - Circuit pre-building to reduce connection latency
//! - Periodic rotation to limit exposure
//! - Health scoring for circuit quality assessment

pub mod health;
pub mod manager;
pub mod pool;
pub mod rotation;

// Re-export main types
pub use health::{
    CircuitHealthMonitor, FailureType, HealthMonitorConfig, HealthStatistics, HealthStatus,
};
pub use manager::{
    CircuitHandle, CircuitManager, CircuitManagerConfig, CircuitManagerEvent,
    CircuitManagerStatistics,
};
pub use pool::{
    CircuitBuilder, CircuitId, CircuitPool, CircuitPoolConfig, PoolCircuit, PoolCircuitState,
    PoolError, PoolEvent, PoolStatistics, RetireReason,
};
pub use rotation::{RotationEvent, RotationPolicy, RotationStatistics, RotationTrigger};

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Builder for constructing a circuit manager with all components
pub struct CircuitManagerBuilder<B: CircuitBuilder + 'static> {
    config: CircuitManagerConfig,
    builder: Arc<B>,
    event_sender: Option<mpsc::Sender<CircuitManagerEvent>>,
}

impl<B: CircuitBuilder> CircuitManagerBuilder<B> {
    /// Create a new builder with default configuration
    pub fn new(builder: Arc<B>) -> Self {
        Self {
            config: CircuitManagerConfig::default(),
            builder,
            event_sender: None,
        }
    }

    /// Create a new builder with custom configuration
    pub fn with_config(builder: Arc<B>, config: CircuitManagerConfig) -> Self {
        Self {
            config,
            builder,
            event_sender: None,
        }
    }

    /// Set the pool configuration
    pub fn pool_config(mut self, config: CircuitPoolConfig) -> Self {
        self.config.pool_config = config;
        self
    }

    /// Set the health monitor configuration
    pub fn health_config(mut self, config: HealthMonitorConfig) -> Self {
        self.config.health_config = config;
        self
    }

    /// Set the rotation policy
    pub fn rotation_policy(mut self, policy: RotationPolicy) -> Self {
        self.config.rotation_policy = policy;
        self
    }

    /// Set the event sender
    pub fn event_sender(mut self, sender: mpsc::Sender<CircuitManagerEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Set maximum concurrent circuits
    pub fn max_concurrent(mut self, max: usize) -> Self {
        self.config.max_concurrent_circuits = max;
        self
    }

    /// Set circuit timeout
    pub fn circuit_timeout(mut self, timeout: Duration) -> Self {
        self.config.circuit_timeout = timeout;
        self
    }

    /// Disable automatic rotation
    pub fn disable_rotation(mut self) -> Self {
        self.config.enable_rotation = false;
        self
    }

    /// Disable health monitoring
    pub fn disable_health_monitoring(mut self) -> Self {
        self.config.enable_health_monitoring = false;
        self
    }

    /// Disable pool management
    pub fn disable_pool_management(mut self) -> Self {
        self.config.enable_pool_management = false;
        self
    }

    /// Build the circuit manager
    pub fn build(self) -> CircuitManager<B> {
        let mut manager = CircuitManager::new(self.config, self.builder);

        if let Some(sender) = self.event_sender {
            manager = manager.with_event_sender(sender);
        }

        manager
    }
}

/// Convenience function to create a circuit manager with default settings
pub fn create_circuit_manager<B: CircuitBuilder>(builder: Arc<B>) -> CircuitManager<B> {
    CircuitManagerBuilder::new(builder).build()
}

/// Convenience function to create a circuit manager with custom pool size
pub fn create_circuit_manager_with_pool<B: CircuitBuilder>(
    builder: Arc<B>,
    min_pool_size: usize,
    max_pool_size: usize,
) -> CircuitManager<B> {
    let pool_config = CircuitPoolConfig {
        min_pool_size,
        max_pool_size,
        pre_build_count: min_pool_size,
        ..Default::default()
    };

    CircuitManagerBuilder::new(builder)
        .pool_config(pool_config)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pool::MockCircuitBuilder;
    use std::time::Duration;

    #[tokio::test]
    async fn test_circuit_manager_builder() {
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = CircuitManagerBuilder::new(builder.clone())
            .max_concurrent(50)
            .circuit_timeout(Duration::from_secs(30))
            .build();

        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_create_circuit_manager() {
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = create_circuit_manager(builder);
        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_create_circuit_manager_with_pool() {
        let builder = Arc::new(MockCircuitBuilder {
            success_rate: 1.0,
            build_delay: Duration::from_millis(10),
        });

        let manager = create_circuit_manager_with_pool(builder, 3, 10);
        assert!(manager.initialize().await.is_ok());

        let stats = manager.get_statistics().await;
        assert!(stats.pool_stats.ready_circuits >= 3);
    }
}
