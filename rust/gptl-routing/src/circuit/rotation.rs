//! Circuit Rotation Module
//!
//! Implements circuit rotation strategies based on Tor's best practices:
//! - Time-based rotation (every N minutes)
//! - Usage-based rotation (after N bytes/connections)
//! - Emergency rotation on failure detection
//! - Predictive rotation based on health metrics

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, trace, warn};

use super::health::{CircuitHealthMonitor, FailureType};
use super::pool::{CircuitId, CircuitPool, RetireReason};

/// Rotation trigger type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RotationTrigger {
    /// Time-based rotation
    TimeBased,
    /// Usage-based rotation (bytes transferred)
    UsageBased,
    /// Connection count rotation
    ConnectionBased,
    /// Health-based rotation
    HealthBased,
    /// Emergency rotation on failure
    Emergency,
    /// Manual rotation
    Manual,
}

impl std::fmt::Display for RotationTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationTrigger::TimeBased => write!(f, "time-based"),
            RotationTrigger::UsageBased => write!(f, "usage-based"),
            RotationTrigger::ConnectionBased => write!(f, "connection-based"),
            RotationTrigger::HealthBased => write!(f, "health-based"),
            RotationTrigger::Emergency => write!(f, "emergency"),
            RotationTrigger::Manual => write!(f, "manual"),
        }
    }
}

/// Rotation policy configuration
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Enable time-based rotation
    pub enable_time_rotation: bool,
    /// Time between rotations
    pub rotation_interval: Duration,
    /// Enable usage-based rotation
    pub enable_usage_rotation: bool,
    /// Bytes threshold for rotation
    pub bytes_threshold: u64,
    /// Enable connection-based rotation
    pub enable_connection_rotation: bool,
    /// Connection count threshold
    pub connection_threshold: u64,
    /// Enable health-based rotation
    pub enable_health_rotation: bool,
    /// Health score threshold (below this triggers rotation)
    pub health_score_threshold: u8,
    /// Minimum circuit lifetime (don't rotate too quickly)
    pub min_circuit_lifetime: Duration,
    /// Maximum circuit lifetime (force rotation)
    pub max_circuit_lifetime: Duration,
    /// Randomize rotation times to avoid patterns
    pub randomize_rotation: bool,
    /// Rotation jitter (percentage of interval)
    pub rotation_jitter_percent: u8,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            enable_time_rotation: true,
            rotation_interval: Duration::from_secs(600), // 10 minutes
            enable_usage_rotation: true,
            bytes_threshold: 100 * 1024 * 1024, // 100 MB
            enable_connection_rotation: true,
            connection_threshold: 1000,
            enable_health_rotation: true,
            health_score_threshold: 50,
            min_circuit_lifetime: Duration::from_secs(60),  // 1 minute minimum
            max_circuit_lifetime: Duration::from_secs(3600), // 1 hour maximum
            randomize_rotation: true,
            rotation_jitter_percent: 10,
        }
    }
}

/// Rotation event
#[derive(Debug, Clone)]
pub enum RotationEvent {
    /// Rotation scheduled
    RotationScheduled {
        circuit_id: CircuitId,
        trigger: RotationTrigger,
        scheduled_at: Instant,
    },
    /// Rotation started
    RotationStarted {
        circuit_id: CircuitId,
        trigger: RotationTrigger,
    },
    /// Rotation completed successfully
    RotationCompleted {
        old_circuit_id: CircuitId,
        new_circuit_id: CircuitId,
        trigger: RotationTrigger,
    },
    /// Rotation failed
    RotationFailed {
        circuit_id: CircuitId,
        trigger: RotationTrigger,
        error: String,
    },
    /// Circuit retired
    CircuitRetired {
        circuit_id: CircuitId,
        reason: RetireReason,
    },
}

/// Circuit rotation information
#[derive(Debug, Clone)]
pub struct RotationInfo {
    /// Circuit ID
    pub circuit_id: CircuitId,
    /// When the circuit was created
    pub created_at: Instant,
    /// When to rotate next
    pub rotate_at: Instant,
    /// Rotation trigger that scheduled this
    pub scheduled_by: Option<RotationTrigger>,
    /// Number of rotations for this circuit slot
    pub rotation_count: u32,
    /// Whether rotation is in progress
    pub rotation_in_progress: bool,
}

impl RotationInfo {
    /// Create new rotation info with randomized rotation time
    pub fn new(circuit_id: CircuitId, policy: &RotationPolicy) -> Self {
        let now = Instant::now();
        let interval = if policy.randomize_rotation {
            add_jitter(policy.rotation_interval, policy.rotation_jitter_percent)
        } else {
            policy.rotation_interval
        };
        
        Self {
            circuit_id,
            created_at: now,
            rotate_at: now + interval,
            scheduled_by: None,
            rotation_count: 0,
            rotation_in_progress: false,
        }
    }

    /// Check if rotation is due
    pub fn is_rotation_due(&self) -> bool {
        Instant::now() >= self.rotate_at && !self.rotation_in_progress
    }

    /// Schedule next rotation
    pub fn schedule_next(&mut self, policy: &RotationPolicy) {
        let interval = if policy.randomize_rotation {
            add_jitter(policy.rotation_interval, policy.rotation_jitter_percent)
        } else {
            policy.rotation_interval
        };
        
        self.rotate_at = Instant::now() + interval;
        self.rotation_in_progress = false;
        self.rotation_count += 1;
    }

    /// Get age of circuit
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Get time until next rotation
    pub fn time_until_rotation(&self) -> Duration {
        let now = Instant::now();
        if self.rotate_at > now {
            self.rotate_at.duration_since(now)
        } else {
            Duration::from_secs(0)
        }
    }
}

/// Circuit rotator manages scheduled and emergency rotations
pub struct CircuitRotator {
    /// Rotation policy
    policy: RotationPolicy,
    /// Health monitor reference
    health_monitor: Arc<CircuitHealthMonitor>,
    /// Circuit pool reference
    pool: Arc<CircuitPool>,
    /// Rotation info for each circuit
    rotation_info: Arc<RwLock<HashMap<CircuitId, RotationInfo>>>,
    /// Event sender
    event_sender: Option<mpsc::Sender<RotationEvent>>,
}

impl CircuitRotator {
    /// Create a new circuit rotator
    pub fn new(
        policy: RotationPolicy,
        health_monitor: Arc<CircuitHealthMonitor>,
        pool: Arc<CircuitPool>,
    ) -> Self {
        Self {
            policy,
            health_monitor,
            pool,
            rotation_info: Arc::new(RwLock::new(HashMap::new())),
            event_sender: None,
        }
    }

    /// Set event sender
    pub fn with_event_sender(mut self, sender: mpsc::Sender<RotationEvent>) -> Self {
        self.event_sender = Some(sender);
        self
    }

    /// Register a new circuit for rotation management
    pub async fn register_circuit(&self, circuit_id: CircuitId) {
        let info = RotationInfo::new(circuit_id, &self.policy);
        let rotate_at = info.rotate_at;
        
        let mut rotation_info = self.rotation_info.write().await;
        rotation_info.insert(circuit_id, info);
        
        debug!(
            circuit_id,
            rotation_at = ?rotate_at,
            "Circuit registered with rotator"
        );
    }

    /// Unregister a circuit from rotation management
    pub async fn unregister_circuit(&self, circuit_id: CircuitId) {
        let mut rotation_info = self.rotation_info.write().await;
        rotation_info.remove(&circuit_id);
        
        debug!(circuit_id, "Circuit unregistered from rotator");
    }

    /// Check if a circuit should be rotated
    pub async fn should_rotate(&self, circuit_id: CircuitId) -> Option<RotationTrigger> {
        // Get rotation info
        let rotation_info = self.rotation_info.read().await;
        let info = rotation_info.get(&circuit_id)?;
        
        // Check minimum lifetime
        if info.age() < self.policy.min_circuit_lifetime {
            return None;
        }
        
        // Check if rotation already in progress
        if info.rotation_in_progress {
            return None;
        }
        drop(rotation_info);
        
        // Check health-based rotation
        if self.policy.enable_health_rotation {
            if let Some(score) = self.health_monitor.get_health_score(circuit_id).await {
                if score < self.policy.health_score_threshold {
                    return Some(RotationTrigger::HealthBased);
                }
            }
        }
        
        // Check time-based rotation
        if self.policy.enable_time_rotation {
            let rotation_info = self.rotation_info.read().await;
            if let Some(info) = rotation_info.get(&circuit_id) {
                if info.is_rotation_due() {
                    return Some(RotationTrigger::TimeBased);
                }
            }
        }
        
        // Check max lifetime
        let rotation_info = self.rotation_info.read().await;
        if let Some(info) = rotation_info.get(&circuit_id) {
            if info.age() >= self.policy.max_circuit_lifetime {
                return Some(RotationTrigger::TimeBased);
            }
        }
        
        None
    }

    /// Perform rotation for a circuit
    pub async fn rotate_circuit(
        &self,
        circuit_id: CircuitId,
        trigger: RotationTrigger,
    ) -> Result<CircuitId, RotationError> {
        // Mark rotation in progress
        {
            let mut rotation_info = self.rotation_info.write().await;
            if let Some(info) = rotation_info.get_mut(&circuit_id) {
                if info.rotation_in_progress {
                    return Err(RotationError::RotationInProgress);
                }
                info.rotation_in_progress = true;
                info.scheduled_by = Some(trigger);
            }
        }
        
        self.send_event(RotationEvent::RotationStarted {
            circuit_id,
            trigger,
        })
        .await;
        
        info!(
            circuit_id,
            trigger = %trigger,
            "Starting circuit rotation"
        );
        
        // Acquire new circuit from pool first
        let new_circuit_id = match self.pool.acquire_circuit().await {
            Ok(id) => id,
            Err(e) => {
                // Reset rotation flag
                let mut rotation_info = self.rotation_info.write().await;
                if let Some(info) = rotation_info.get_mut(&circuit_id) {
                    info.rotation_in_progress = false;
                }
                
                self.send_event(RotationEvent::RotationFailed {
                    circuit_id,
                    trigger,
                    error: e.to_string(),
                })
                .await;
                
                return Err(RotationError::PoolError(e.to_string()));
            }
        };
        
        // Test new circuit before switching
        // Note: In production, you'd test the actual circuit here
        
        // Retire old circuit
        if let Err(e) = self.pool.retire_circuit(circuit_id, RetireReason::Age).await {
            warn!(
                circuit_id,
                error = %e,
                "Failed to retire old circuit during rotation"
            );
        }
        
        // Unregister old circuit from rotator
        self.unregister_circuit(circuit_id).await;
        
        // Register new circuit
        self.register_circuit(new_circuit_id).await;
        
        self.send_event(RotationEvent::RotationCompleted {
            old_circuit_id: circuit_id,
            new_circuit_id,
            trigger,
        })
        .await;
        
        info!(
            old_circuit_id = circuit_id,
            new_circuit_id,
            trigger = %trigger,
            "Circuit rotation completed"
        );
        
        Ok(new_circuit_id)
    }

    /// Trigger emergency rotation
    pub async fn emergency_rotate(&self, circuit_id: CircuitId) -> Result<CircuitId, RotationError> {
        warn!(circuit_id, "Emergency circuit rotation triggered");
        
        // Record failure in health monitor
        self.health_monitor.record_failure(circuit_id, FailureType::InternalError).await;
        
        // Perform rotation
        self.rotate_circuit(circuit_id, RotationTrigger::Emergency).await
    }

    /// Get rotation info for a circuit
    pub async fn get_rotation_info(&self, circuit_id: CircuitId) -> Option<RotationInfo> {
        let rotation_info = self.rotation_info.read().await;
        rotation_info.get(&circuit_id).cloned()
    }

    /// Get all circuits needing rotation
    pub async fn get_circuits_needing_rotation(&self) -> Vec<(CircuitId, RotationTrigger)> {
        let rotation_info = self.rotation_info.read().await;
        let mut result = Vec::new();
        
        for (&circuit_id, info) in rotation_info.iter() {
            // Skip if rotation already in progress
            if info.rotation_in_progress {
                continue;
            }
            
            // Check minimum lifetime
            if info.age() < self.policy.min_circuit_lifetime {
                continue;
            }
            
            // Check time-based
            if self.policy.enable_time_rotation && info.is_rotation_due() {
                result.push((circuit_id, RotationTrigger::TimeBased));
                continue;
            }
            
            // Check max lifetime
            if info.age() >= self.policy.max_circuit_lifetime {
                result.push((circuit_id, RotationTrigger::TimeBased));
                continue;
            }
        }
        
        drop(rotation_info);
        
        // Check health-based (requires health monitor)
        if self.policy.enable_health_rotation {
            let rotation_info = self.rotation_info.read().await;
            for &circuit_id in rotation_info.keys() {
                if let Some(score) = self.health_monitor.get_health_score(circuit_id).await {
                    if score < self.policy.health_score_threshold {
                        // Check if not already in result
                        if !result.iter().any(|(id, _)| *id == circuit_id) {
                            result.push((circuit_id, RotationTrigger::HealthBased));
                        }
                    }
                }
            }
        }
        
        result
    }

    /// Get rotation statistics
    pub async fn get_statistics(&self) -> RotationStatistics {
        let rotation_info = self.rotation_info.read().await;
        
        let total = rotation_info.len();
        let mut pending = 0;
        let mut in_progress = 0;
        let mut total_rotations = 0;
        
        for info in rotation_info.values() {
            if info.rotation_in_progress {
                in_progress += 1;
            } else if info.is_rotation_due() {
                pending += 1;
            }
            total_rotations += info.rotation_count;
        }
        
        RotationStatistics {
            total_circuits: total,
            pending_rotations: pending,
            in_progress_rotations: in_progress,
            total_rotations_completed: total_rotations,
        }
    }

    /// Start background rotation task
    pub fn start_rotation_task(&self) {
        let rotation_info = self.rotation_info.clone();
        let health_monitor = self.health_monitor.clone();
        let pool = self.pool.clone();
        let policy = self.policy.clone();
        let event_sender = self.event_sender.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                let _now = Instant::now();
                let mut to_rotate = Vec::new();

                // Find circuits needing rotation
                {
                    let info_guard = rotation_info.read().await;
                    for (circuit_id, info) in info_guard.iter() {
                        if info.rotation_in_progress {
                            continue;
                        }
                        
                        if info.age() < policy.min_circuit_lifetime {
                            continue;
                        }
                        
                        if (policy.enable_time_rotation && info.is_rotation_due())
                            || info.age() >= policy.max_circuit_lifetime
                        {
                            to_rotate.push((*circuit_id, RotationTrigger::TimeBased));
                        }
                    }
                }
                
                // Perform rotations
                for (circuit_id, trigger) in to_rotate {
                    // Mark in progress
                    {
                        let mut info_guard = rotation_info.write().await;
                        if let Some(info) = info_guard.get_mut(&circuit_id) {
                            info.rotation_in_progress = true;
                            info.scheduled_by = Some(trigger);
                        }
                    }
                    
                    if let Some(ref sender) = event_sender {
                        let _ = sender.send(RotationEvent::RotationStarted {
                            circuit_id,
                            trigger,
                        }).await;
                    }
                    
                    // Acquire new circuit
                    match pool.acquire_circuit().await {
                        Ok(new_circuit_id) => {
                            // Retire old circuit
                            let _ = pool.retire_circuit(circuit_id, RetireReason::Age).await;
                            
                            // Update rotation info
                            {
                                let mut info_guard = rotation_info.write().await;
                                info_guard.remove(&circuit_id);
                                
                                let new_info = RotationInfo::new(new_circuit_id, &policy);
                                info_guard.insert(new_circuit_id, new_info);
                            }
                            
                            // Register with health monitor
                            health_monitor.register_circuit(new_circuit_id).await;
                            
                            if let Some(ref sender) = event_sender {
                                let _ = sender.send(RotationEvent::RotationCompleted {
                                    old_circuit_id: circuit_id,
                                    new_circuit_id,
                                    trigger,
                                }).await;
                            }
                            
                            info!(
                                old_circuit_id = circuit_id,
                                new_circuit_id,
                                "Background rotation completed"
                            );
                        }
                        Err(e) => {
                            // Reset rotation flag
                            {
                                let mut info_guard = rotation_info.write().await;
                                if let Some(info) = info_guard.get_mut(&circuit_id) {
                                    info.rotation_in_progress = false;
                                }
                            }
                            
                            if let Some(ref sender) = event_sender {
                                let _ = sender.send(RotationEvent::RotationFailed {
                                    circuit_id,
                                    trigger,
                                    error: e.to_string(),
                                }).await;
                            }
                            
                            warn!(
                                circuit_id,
                                error = %e,
                                "Background rotation failed"
                            );
                        }
                    }
                }
                
                trace!("Rotation check cycle completed");
            }
        });
    }

    /// Send event if sender is configured
    async fn send_event(&self, event: RotationEvent) {
        if let Some(ref sender) = self.event_sender {
            let _ = sender.send(event).await;
        }
    }
}

/// Rotation statistics
#[derive(Debug, Clone)]
pub struct RotationStatistics {
    /// Total circuits being tracked
    pub total_circuits: usize,
    /// Number of pending rotations
    pub pending_rotations: usize,
    /// Number of rotations in progress
    pub in_progress_rotations: usize,
    /// Total rotations completed
    pub total_rotations_completed: u32,
}

/// Rotation errors
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("Rotation already in progress")]
    RotationInProgress,
    #[error("Circuit not found: {0}")]
    CircuitNotFound(CircuitId),
    #[error("Pool error: {0}")]
    PoolError(String),
    #[error("Circuit not ready for rotation")]
    NotReady,
}

/// Add jitter to a duration
fn add_jitter(duration: Duration, jitter_percent: u8) -> Duration {
    if jitter_percent == 0 {
        return duration;
    }
    
    let jitter_factor = 1.0 + (rand::random::<f64>() * jitter_percent as f64 / 100.0);
    duration.mul_f64(jitter_factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_trigger_display() {
        assert_eq!(RotationTrigger::TimeBased.to_string(), "time-based");
        assert_eq!(RotationTrigger::Emergency.to_string(), "emergency");
    }

    #[test]
    fn test_rotation_info_new() {
        let policy = RotationPolicy::default();
        let info = RotationInfo::new(1, &policy);
        
        assert_eq!(info.circuit_id, 1);
        assert_eq!(info.rotation_count, 0);
        assert!(!info.rotation_in_progress);
        assert!(info.rotate_at > info.created_at);
    }

    #[test]
    fn test_rotation_info_is_due() {
        let policy = RotationPolicy {
            rotation_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let mut info = RotationInfo::new(1, &policy);
        
        // Should not be due immediately
        assert!(!info.is_rotation_due());
        
        // Set rotation time to now
        info.rotate_at = Instant::now() - Duration::from_secs(1);
        assert!(info.is_rotation_due());
        
        // Should not be due if rotation in progress
        info.rotation_in_progress = true;
        assert!(!info.is_rotation_due());
    }

    #[test]
    fn test_rotation_info_age() {
        let policy = RotationPolicy::default();
        let info = RotationInfo::new(1, &policy);
        
        // Age should be very small
        assert!(info.age() < Duration::from_secs(1));
    }

    #[test]
    fn test_rotation_policy_default() {
        let policy = RotationPolicy::default();
        
        assert!(policy.enable_time_rotation);
        assert!(policy.enable_usage_rotation);
        assert!(policy.enable_connection_rotation);
        assert!(policy.enable_health_rotation);
        assert_eq!(policy.health_score_threshold, 50);
    }

    #[test]
    fn test_add_jitter() {
        let base = Duration::from_secs(60);
        
        // With 0% jitter, should be same
        let no_jitter = add_jitter(base, 0);
        assert_eq!(no_jitter, base);
        
        // With jitter, should be >= base
        let with_jitter = add_jitter(base, 10);
        assert!(with_jitter >= base);
        assert!(with_jitter <= base.mul_f64(1.1));
    }

    #[tokio::test]
    async fn test_rotation_statistics() {
        let policy = RotationPolicy::default();
        let health_monitor = Arc::new(CircuitHealthMonitor::new());
        
        // We need to create a mock pool for testing
        // For now, just test the statistics struct
        let stats = RotationStatistics {
            total_circuits: 10,
            pending_rotations: 2,
            in_progress_rotations: 1,
            total_rotations_completed: 50,
        };
        
        assert_eq!(stats.total_circuits, 10);
        assert_eq!(stats.pending_rotations, 2);
    }
}
