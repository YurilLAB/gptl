//! Circuit Health Monitoring Module
//!
//! Implements comprehensive health tracking for circuits based on Tor best practices:
//! - Exponentially Weighted Moving Average (EWMA) for latency tracking
//! - Failure detection with configurable thresholds
//! - Health scoring (0-100) for circuit quality assessment
//! - Automatic degradation detection and reporting

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

/// Health status of a circuit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthStatus {
    /// Circuit is healthy and performing well
    Healthy,
    /// Circuit is experiencing minor issues but still usable
    Degraded,
    /// Circuit has significant problems, should be replaced
    Unhealthy,
    /// Circuit has failed and is no longer usable
    Failed,
}

impl HealthStatus {
    /// Check if the circuit is usable
    pub fn is_usable(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }

    /// Get numeric representation (higher is better)
    pub fn score(&self) -> u8 {
        match self {
            HealthStatus::Healthy => 100,
            HealthStatus::Degraded => 50,
            HealthStatus::Unhealthy => 25,
            HealthStatus::Failed => 0,
        }
    }
}

/// Metrics for a single circuit
#[derive(Debug, Clone)]
pub struct CircuitMetrics {
    /// Circuit ID
    pub circuit_id: u64,
    /// Current health status
    pub status: HealthStatus,
    /// Overall health score (0-100)
    pub health_score: u8,
    /// Latency measurements (EWMA values)
    pub latency_ewma: f64,
    /// Half-life for EWMA calculation in seconds
    pub ewma_half_life: Duration,
    /// Last measurement time
    pub last_measurement: Instant,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Number of successful requests
    pub successful_requests: u64,
    /// Number of failed requests
    pub failed_requests: u64,
    /// Recent latency samples (for variance calculation)
    pub latency_samples: VecDeque<Duration>,
    /// Recent failure timestamps
    pub recent_failures: VecDeque<Instant>,
    /// Circuit creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Consecutive failures
    pub consecutive_failures: u32,
}

impl CircuitMetrics {
    /// Create new metrics for a circuit
    pub fn new(circuit_id: u64) -> Self {
        let now = Instant::now();
        Self {
            circuit_id,
            status: HealthStatus::Healthy,
            health_score: 100,
            latency_ewma: 0.0,
            ewma_half_life: Duration::from_secs(10),
            last_measurement: now,
            bytes_transferred: 0,
            successful_requests: 0,
            failed_requests: 0,
            latency_samples: VecDeque::with_capacity(100),
            recent_failures: VecDeque::with_capacity(50),
            created_at: now,
            last_activity: now,
            consecutive_failures: 0,
        }
    }

    /// Record a successful request with latency
    pub fn record_success(&mut self, latency: Duration, bytes: u64) {
        let now = Instant::now();
        
        // Update EWMA latency using Tor's formula: A_{t+Δt} = A_t * 0.5^(Δt/H)
        let delta_t = now.duration_since(self.last_measurement).as_secs_f64();
        let half_life_secs = self.ewma_half_life.as_secs_f64();
        let decay = 0.5f64.powf(delta_t / half_life_secs);
        
        let latency_ms = latency.as_millis() as f64;
        // Correct EWMA: new = old * α + sample * (1 - α)
        self.latency_ewma = self.latency_ewma * decay + latency_ms * (1.0 - decay);
        
        self.last_measurement = now;
        self.last_activity = now;
        self.bytes_transferred += bytes;
        self.successful_requests += 1;
        self.consecutive_failures = 0;
        
        // Keep last 100 latency samples
        self.latency_samples.push_back(latency);
        while self.latency_samples.len() > 100 {
            self.latency_samples.pop_front();
        }
        
        // Update health status
        self.update_health_score();
        
        trace!(
            circuit_id = self.circuit_id,
            latency_ms = latency.as_millis() as u64,
            ewma = self.latency_ewma,
            "Circuit success recorded"
        );
    }

    /// Record a failed request
    pub fn record_failure(&mut self, _failure_type: FailureType) {
        let now = Instant::now();
        
        self.failed_requests += 1;
        self.consecutive_failures += 1;
        self.last_activity = now;
        
        // Record failure timestamp
        self.recent_failures.push_back(now);
        
        // Remove failures older than 5 minutes
        let cutoff = now - Duration::from_secs(300);
        while let Some(oldest) = self.recent_failures.front() {
            if *oldest < cutoff {
                self.recent_failures.pop_front();
            } else {
                break;
            }
        }
        
        // Update health status
        self.update_health_score();
        
        warn!(
            circuit_id = self.circuit_id,
            consecutive_failures = self.consecutive_failures,
            total_failures = self.failed_requests,
            "Circuit failure recorded"
        );
    }

    /// Update the health score based on current metrics
    fn update_health_score(&mut self) {
        let mut score = 100u8;
        
        // Deduct for high latency EWMA (> 2 seconds)
        if self.latency_ewma > 2000.0 {
            score = score.saturating_sub(20);
        } else if self.latency_ewma > 1000.0 {
            score = score.saturating_sub(10);
        }
        
        // Deduct for recent failures
        let recent_failure_count = self.recent_failures.len() as u8;
        score = score.saturating_sub(recent_failure_count * 10);
        
        // Deduct for consecutive failures
        score = score.saturating_sub(self.consecutive_failures as u8 * 15);
        
        // Deduct for high failure rate
        let total_requests = self.successful_requests + self.failed_requests;
        if total_requests > 10 {
            let failure_rate = self.failed_requests as f64 / total_requests as f64;
            if failure_rate > 0.5 {
                score = score.saturating_sub(30);
            } else if failure_rate > 0.25 {
                score = score.saturating_sub(15);
            }
        }
        
        // Deduct for high latency variance
        if self.latency_samples.len() >= 10 {
            let variance = self.calculate_latency_variance();
            if variance > 1000.0 {
                score = score.saturating_sub(10);
            }
        }
        
        self.health_score = score;
        
        // Update status based on score
        self.status = match score {
            80..=100 => HealthStatus::Healthy,
            50..=79 => HealthStatus::Degraded,
            20..=49 => HealthStatus::Unhealthy,
            _ => HealthStatus::Failed,
        };
    }

    /// Calculate latency variance (standard deviation)
    fn calculate_latency_variance(&self) -> f64 {
        if self.latency_samples.len() < 2 {
            return 0.0;
        }
        
        let samples: Vec<f64> = self.latency_samples
            .iter()
            .map(|d| d.as_millis() as f64)
            .collect();
        
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let variance = samples.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / samples.len() as f64;
        
        variance.sqrt()
    }

    /// Get current average latency
    pub fn average_latency(&self) -> Duration {
        if self.latency_samples.is_empty() {
            return Duration::from_millis(0);
        }
        
        let sum: u128 = self.latency_samples.iter().map(|d| d.as_millis()).sum();
        let avg = sum / self.latency_samples.len() as u128;
        Duration::from_millis(avg as u64)
    }

    /// Get failure rate (0.0 to 1.0)
    pub fn failure_rate(&self) -> f64 {
        let total = self.successful_requests + self.failed_requests;
        if total == 0 {
            0.0
        } else {
            self.failed_requests as f64 / total as f64
        }
    }

    /// Check if circuit needs rotation due to age
    pub fn should_rotate_due_to_age(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.created_at) > max_age
    }

    /// Check if circuit needs rotation due to usage
    pub fn should_rotate_due_to_usage(&self, max_bytes: u64, max_requests: u64) -> bool {
        self.bytes_transferred >= max_bytes || 
        (self.successful_requests + self.failed_requests) >= max_requests
    }

    /// Get age of the circuit
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }
}

/// Types of failures that can occur
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureType {
    /// Connection timeout
    Timeout,
    /// Connection refused or reset
    ConnectionFailed,
    /// Protocol error
    ProtocolError,
    /// High latency detected
    HighLatency,
    /// Packet loss detected
    PacketLoss,
    /// Circuit deliberately closed
    DeliberateClose,
    /// Internal error
    InternalError,
}

/// Configuration for health monitoring
#[derive(Debug, Clone)]
pub struct HealthMonitorConfig {
    /// Maximum latency threshold for healthy circuits
    pub max_latency_threshold: Duration,
    /// Maximum consecutive failures before marking unhealthy
    pub max_consecutive_failures: u32,
    /// Maximum failure rate (0.0 to 1.0)
    pub max_failure_rate: f64,
    /// Maximum circuit age before rotation
    pub max_circuit_age: Duration,
    /// Maximum bytes before rotation
    pub max_bytes_before_rotation: u64,
    /// Maximum requests before rotation
    pub max_requests_before_rotation: u64,
    /// EWMA half-life for latency calculation
    pub ewma_half_life: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Idle timeout for unused circuits
    pub idle_timeout: Duration,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            max_latency_threshold: Duration::from_secs(5),
            max_consecutive_failures: 3,
            max_failure_rate: 0.3,
            max_circuit_age: Duration::from_secs(600), // 10 minutes
            max_bytes_before_rotation: 100 * 1024 * 1024, // 100 MB
            max_requests_before_rotation: 1000,
            ewma_half_life: Duration::from_secs(10),
            health_check_interval: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Circuit health monitor
pub struct CircuitHealthMonitor {
    /// Configuration
    config: HealthMonitorConfig,
    /// Metrics for each circuit
    metrics: Arc<RwLock<HashMap<u64, CircuitMetrics>>>,
    /// Circuit IDs sorted by health score (ascending)
    health_ranking: Arc<RwLock<Vec<u64>>>,
}

impl CircuitHealthMonitor {
    /// Create a new health monitor with default configuration
    pub fn new() -> Self {
        Self::with_config(HealthMonitorConfig::default())
    }

    /// Create a new health monitor with custom configuration
    pub fn with_config(config: HealthMonitorConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            health_ranking: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a new circuit for monitoring
    pub async fn register_circuit(&self, circuit_id: u64) {
        let mut metrics = self.metrics.write().await;
        let circuit_metrics = CircuitMetrics::new(circuit_id);
        metrics.insert(circuit_id, circuit_metrics);
        
        let mut ranking = self.health_ranking.write().await;
        ranking.push(circuit_id);
        
        debug!(circuit_id, "Circuit registered with health monitor");
    }

    /// Unregister a circuit from monitoring
    pub async fn unregister_circuit(&self, circuit_id: u64) {
        let mut metrics = self.metrics.write().await;
        metrics.remove(&circuit_id);
        
        let mut ranking = self.health_ranking.write().await;
        ranking.retain(|&id| id != circuit_id);
        
        debug!(circuit_id, "Circuit unregistered from health monitor");
    }

    /// Record a successful request for a circuit
    pub async fn record_success(&self, circuit_id: u64, latency: Duration, bytes: u64) {
        {
            let mut metrics = self.metrics.write().await;

            if let Some(circuit_metrics) = metrics.get_mut(&circuit_id) {
                circuit_metrics.record_success(latency, bytes);
            } else {
                // Auto-register if not exists
                drop(metrics);
                self.register_circuit(circuit_id).await;

                let mut metrics = self.metrics.write().await;
                if let Some(circuit_metrics) = metrics.get_mut(&circuit_id) {
                    circuit_metrics.record_success(latency, bytes);
                }
            }
            // Lock dropped here before update_health_ranking acquires read lock
        }

        // Update health ranking periodically
        self.update_health_ranking().await;
    }

    /// Record a failed request for a circuit
    pub async fn record_failure(&self, circuit_id: u64, failure_type: FailureType) {
        {
            let mut metrics = self.metrics.write().await;

            if let Some(circuit_metrics) = metrics.get_mut(&circuit_id) {
                circuit_metrics.record_failure(failure_type);
            } else {
                // Auto-register if not exists
                drop(metrics);
                self.register_circuit(circuit_id).await;

                let mut metrics = self.metrics.write().await;
                if let Some(circuit_metrics) = metrics.get_mut(&circuit_id) {
                    circuit_metrics.record_failure(failure_type);
                }
            }
            // Lock dropped here before update_health_ranking acquires read lock
        }

        self.update_health_ranking().await;
    }

    /// Get health status for a circuit
    pub async fn get_health_status(&self, circuit_id: u64) -> Option<HealthStatus> {
        let metrics = self.metrics.read().await;
        metrics.get(&circuit_id).map(|m| m.status)
    }

    /// Get health score for a circuit
    pub async fn get_health_score(&self, circuit_id: u64) -> Option<u8> {
        let metrics = self.metrics.read().await;
        metrics.get(&circuit_id).map(|m| m.health_score)
    }

    /// Get full metrics for a circuit
    pub async fn get_metrics(&self, circuit_id: u64) -> Option<CircuitMetrics> {
        let metrics = self.metrics.read().await;
        metrics.get(&circuit_id).cloned()
    }

    /// Check if circuit needs rotation
    pub async fn needs_rotation(&self, circuit_id: u64) -> bool {
        let metrics = self.metrics.read().await;
        
        if let Some(m) = metrics.get(&circuit_id) {
            // Check health status
            if matches!(m.status, HealthStatus::Unhealthy | HealthStatus::Failed) {
                return true;
            }
            
            // Check age
            if m.should_rotate_due_to_age(self.config.max_circuit_age) {
                return true;
            }
            
            // Check usage
            if m.should_rotate_due_to_usage(
                self.config.max_bytes_before_rotation,
                self.config.max_requests_before_rotation
            ) {
                return true;
            }
            
            // Check consecutive failures
            if m.consecutive_failures >= self.config.max_consecutive_failures {
                return true;
            }
            
            // Check idle timeout
            if m.idle_time() > self.config.idle_timeout {
                return true;
            }
            
            // Check failure rate
            if m.failure_rate() > self.config.max_failure_rate {
                return true;
            }
        }
        
        false
    }

    /// Get the healthiest circuit from a list of candidates
    pub async fn get_healthiest_circuit(&self, candidates: &[u64]) -> Option<u64> {
        let metrics = self.metrics.read().await;
        
        let mut best_id = None;
        let mut best_score = 0u8;
        
        for &circuit_id in candidates {
            if let Some(m) = metrics.get(&circuit_id) {
                if m.status.is_usable() && m.health_score > best_score {
                    best_score = m.health_score;
                    best_id = Some(circuit_id);
                }
            }
        }
        
        best_id
    }

    /// Get circuits sorted by health score (best first)
    pub async fn get_circuits_by_health(&self) -> Vec<(u64, u8)> {
        let metrics = self.metrics.read().await;
        
        let mut circuits: Vec<(u64, u8)> = metrics
            .iter()
            .filter(|(_, m)| m.status.is_usable())
            .map(|(&id, m)| (id, m.health_score))
            .collect();
        
        // Sort by health score descending
        circuits.sort_by(|a, b| b.1.cmp(&a.1));
        
        circuits
    }

    /// Get all unhealthy circuits that should be rotated
    pub async fn get_unhealthy_circuits(&self) -> Vec<u64> {
        let metrics = self.metrics.read().await;
        
        metrics
            .iter()
            .filter(|(_, m)| {
                matches!(m.status, HealthStatus::Unhealthy | HealthStatus::Failed)
            })
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get statistics summary
    pub async fn get_statistics(&self) -> HealthStatistics {
        let metrics = self.metrics.read().await;
        
        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;
        let mut failed = 0;
        let mut total_latency = Duration::from_millis(0);
        let mut total_bytes = 0u64;
        
        for m in metrics.values() {
            match m.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Unhealthy => unhealthy += 1,
                HealthStatus::Failed => failed += 1,
            }
            total_latency += m.average_latency();
            total_bytes += m.bytes_transferred;
        }
        
        let count = metrics.len();
        let avg_latency = if count > 0 {
            total_latency / count as u32
        } else {
            Duration::from_millis(0)
        };
        
        HealthStatistics {
            total_circuits: count,
            healthy_circuits: healthy,
            degraded_circuits: degraded,
            unhealthy_circuits: unhealthy,
            failed_circuits: failed,
            average_latency: avg_latency,
            total_bytes_transferred: total_bytes,
        }
    }

    /// Update health ranking
    async fn update_health_ranking(&self) {
        let metrics = self.metrics.read().await;
        let mut ranking = self.health_ranking.write().await;
        
        // Get all circuit IDs with their scores
        let mut scored: Vec<(u64, u8)> = metrics
            .iter()
            .map(|(&id, m)| (id, m.health_score))
            .collect();
        
        // Sort by score ascending (unhealthy first for quick access)
        scored.sort_by(|a, b| a.1.cmp(&b.1));
        
        *ranking = scored.into_iter().map(|(id, _)| id).collect();
    }

    /// Start background health check task
    pub fn start_health_check_task(&self) {
        let metrics = self.metrics.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.health_check_interval);
            
            loop {
                interval.tick().await;
                
                let mut metrics_guard = metrics.write().await;
                let now = Instant::now();
                
                // Update all metrics
                for (circuit_id, m) in metrics_guard.iter_mut() {
                    // Check for stale circuits
                    if m.idle_time() > config.idle_timeout {
                        warn!(circuit_id = *circuit_id, "Circuit idle timeout detected");
                    }
                    
                    // Recalculate health scores
                    m.update_health_score();
                    m.last_measurement = now;
                }
                
                drop(metrics_guard);
                
                trace!("Health check cycle completed");
            }
        });
    }
}

impl Default for CircuitHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Health statistics summary
#[derive(Debug, Clone)]
pub struct HealthStatistics {
    /// Total number of tracked circuits
    pub total_circuits: usize,
    /// Number of healthy circuits
    pub healthy_circuits: usize,
    /// Number of degraded circuits
    pub degraded_circuits: usize,
    /// Number of unhealthy circuits
    pub unhealthy_circuits: usize,
    /// Number of failed circuits
    pub failed_circuits: usize,
    /// Average latency across all circuits
    pub average_latency: Duration,
    /// Total bytes transferred
    pub total_bytes_transferred: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_usable());
        assert!(HealthStatus::Degraded.is_usable());
        assert!(!HealthStatus::Unhealthy.is_usable());
        assert!(!HealthStatus::Failed.is_usable());
        
        assert_eq!(HealthStatus::Healthy.score(), 100);
        assert_eq!(HealthStatus::Failed.score(), 0);
    }

    #[test]
    fn test_circuit_metrics_new() {
        let metrics = CircuitMetrics::new(1);
        assert_eq!(metrics.circuit_id, 1);
        assert_eq!(metrics.health_score, 100);
        assert_eq!(metrics.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_circuit_metrics_success() {
        let mut metrics = CircuitMetrics::new(1);
        
        metrics.record_success(Duration::from_millis(100), 1024);
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.bytes_transferred, 1024);
        assert_eq!(metrics.consecutive_failures, 0);
        
        metrics.record_success(Duration::from_millis(200), 512);
        assert_eq!(metrics.successful_requests, 2);
    }

    #[test]
    fn test_circuit_metrics_failure() {
        let mut metrics = CircuitMetrics::new(1);
        
        metrics.record_failure(FailureType::Timeout);
        assert_eq!(metrics.failed_requests, 1);
        assert_eq!(metrics.consecutive_failures, 1);
        
        metrics.record_failure(FailureType::ConnectionFailed);
        assert_eq!(metrics.failed_requests, 2);
        assert_eq!(metrics.consecutive_failures, 2);
    }

    #[test]
    fn test_circuit_metrics_health_degradation() {
        let mut metrics = CircuitMetrics::new(1);
        
        // Multiple failures should degrade health
        for _ in 0..5 {
            metrics.record_failure(FailureType::Timeout);
        }
        
        assert!(metrics.health_score < 100);
        assert!(matches!(metrics.status, HealthStatus::Degraded | HealthStatus::Unhealthy | HealthStatus::Failed));
    }

    #[test]
    fn test_failure_rate() {
        let mut metrics = CircuitMetrics::new(1);
        
        assert_eq!(metrics.failure_rate(), 0.0);
        
        metrics.record_failure(FailureType::Timeout);
        assert_eq!(metrics.failure_rate(), 1.0);
        
        metrics.record_success(Duration::from_millis(100), 100);
        assert_eq!(metrics.failure_rate(), 0.5);
    }

    #[test]
    fn test_circuit_metrics_rotation_checks() {
        let mut metrics = CircuitMetrics::new(1);
        
        // Age check
        assert!(!metrics.should_rotate_due_to_age(Duration::from_secs(3600)));
        
        // Usage checks
        assert!(!metrics.should_rotate_due_to_usage(1000, 100));
        
        metrics.bytes_transferred = 1001;
        assert!(metrics.should_rotate_due_to_usage(1000, 100));
    }

    #[tokio::test]
    async fn test_health_monitor_register() {
        let monitor = CircuitHealthMonitor::new();
        
        monitor.register_circuit(1).await;
        
        let status = monitor.get_health_status(1).await;
        assert!(status.is_some());
        assert_eq!(status.unwrap(), HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_monitor_record_success() {
        let monitor = CircuitHealthMonitor::new();
        
        monitor.record_success(1, Duration::from_millis(100), 1024).await;
        
        let metrics = monitor.get_metrics(1).await.unwrap();
        assert_eq!(metrics.successful_requests, 1);
        assert_eq!(metrics.bytes_transferred, 1024);
    }

    #[tokio::test]
    async fn test_health_monitor_get_healthiest() {
        let monitor = CircuitHealthMonitor::new();
        
        // Register circuits
        monitor.register_circuit(1).await;
        monitor.register_circuit(2).await;
        
        // Record failures for circuit 1
        monitor.record_failure(1, FailureType::Timeout).await;
        monitor.record_failure(1, FailureType::Timeout).await;
        
        // Record success for circuit 2
        monitor.record_success(2, Duration::from_millis(100), 100).await;
        
        // Circuit 2 should be healthiest
        let healthiest = monitor.get_healthiest_circuit(&[1, 2]).await;
        assert_eq!(healthiest, Some(2));
    }

    #[tokio::test]
    async fn test_health_monitor_needs_rotation() {
        let monitor = CircuitHealthMonitor::new();
        
        monitor.register_circuit(1).await;
        
        // Initially shouldn't need rotation
        assert!(!monitor.needs_rotation(1).await);
        
        // After failures, should need rotation
        for _ in 0..5 {
            monitor.record_failure(1, FailureType::Timeout).await;
        }
        
        assert!(monitor.needs_rotation(1).await);
    }

    #[tokio::test]
    async fn test_health_monitor_statistics() {
        let monitor = CircuitHealthMonitor::new();
        
        monitor.register_circuit(1).await;
        monitor.register_circuit(2).await;
        
        monitor.record_success(1, Duration::from_millis(100), 1000).await;
        monitor.record_success(2, Duration::from_millis(200), 2000).await;
        
        let stats = monitor.get_statistics().await;
        assert_eq!(stats.total_circuits, 2);
        assert_eq!(stats.healthy_circuits, 2);
        assert_eq!(stats.total_bytes_transferred, 3000);
    }
}
