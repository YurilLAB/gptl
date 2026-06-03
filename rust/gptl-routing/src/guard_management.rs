//! Guard Management Module
//!
//! Implements countermeasures against guard discovery attacks (Overlier-Syverson)
//! including vanguards, layered guards, and rotation policies.

use super::{GuardInfo, GuardLayer, RoutingConfig, RoutingError};
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Guard manager for secure guard selection and rotation
pub struct GuardManager {
    config: Arc<RwLock<RoutingConfig>>,
    /// First layer guards (entry)
    first_layer: Arc<RwLock<Vec<GuardEntry>>>,
    /// Second layer guards (middle/vanguards)
    second_layer: Arc<RwLock<Vec<GuardEntry>>>,
    /// Third layer guards (additional protection)
    third_layer: Arc<RwLock<Vec<GuardEntry>>>,
    /// Rotation scheduler
    rotation_scheduler: Arc<RwLock<RotationScheduler>>,
    /// Guard usage statistics
    usage_stats: Arc<RwLock<HashMap<String, GuardStats>>>,
}

/// Guard entry with metadata
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GuardEntry {
    info: GuardInfo,
    added_at: Instant,
    last_used: Option<Instant>,
    use_count: u64,
    failure_count: u64,
    reputation: f64,
}

/// Guard statistics
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
struct GuardStats {
    total_circuits: u64,
    failed_circuits: u64,
    bytes_transferred: u64,
    avg_latency: Duration,
}

/// Rotation scheduler
#[derive(Debug, Clone)]
struct RotationScheduler {
    /// First layer rotation interval
    first_layer_interval: Duration,
    /// Second layer rotation interval
    second_layer_interval: Duration,
    /// Third layer rotation interval
    third_layer_interval: Duration,
    /// Last rotation times
    last_rotations: HashMap<GuardLayer, Instant>,
}

impl GuardManager {
    /// Create new guard manager
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        let first_layer = Arc::new(RwLock::new(Vec::new()));
        let second_layer = Arc::new(RwLock::new(Vec::new()));
        let third_layer = Arc::new(RwLock::new(Vec::new()));

        let rotation_scheduler = Arc::new(RwLock::new(RotationScheduler {
            first_layer_interval: Duration::from_secs(90 * 24 * 60 * 60), // 90 days
            second_layer_interval: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            third_layer_interval: Duration::from_secs(7 * 24 * 60 * 60),  // 7 days
            last_rotations: HashMap::new(),
        }));

        let usage_stats = Arc::new(RwLock::new(HashMap::new()));

        Self {
            config,
            first_layer,
            second_layer,
            third_layer,
            rotation_scheduler,
            usage_stats,
        }
    }

    /// Initialize guard manager
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        // Start rotation check task
        let scheduler = self.rotation_scheduler.clone();
        let first_layer = self.first_layer.clone();
        let second_layer = self.second_layer.clone();
        let third_layer = self.third_layer.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Check hourly
            loop {
                interval.tick().await;

                let mut sched = scheduler.write().await;
                let now = Instant::now();

                // Check first layer
                if let Some(last) = sched.last_rotations.get(&GuardLayer::First) {
                    if now.duration_since(*last) > sched.first_layer_interval {
                        let mut layer = first_layer.write().await;
                        Self::rotate_layer(&mut layer, GuardLayer::First);
                        sched.last_rotations.insert(GuardLayer::First, now);
                    }
                }

                // Check second layer
                if let Some(last) = sched.last_rotations.get(&GuardLayer::Second) {
                    if now.duration_since(*last) > sched.second_layer_interval {
                        let mut layer = second_layer.write().await;
                        Self::rotate_layer(&mut layer, GuardLayer::Second);
                        sched.last_rotations.insert(GuardLayer::Second, now);
                    }
                }

                // Check third layer
                if let Some(last) = sched.last_rotations.get(&GuardLayer::Third) {
                    if now.duration_since(*last) > sched.third_layer_interval {
                        let mut layer = third_layer.write().await;
                        Self::rotate_layer(&mut layer, GuardLayer::Third);
                        sched.last_rotations.insert(GuardLayer::Third, now);
                    }
                }
            }
        });

        Ok(())
    }

    /// Select guards for circuit
    pub async fn select_guards(&self) -> Result<Vec<GuardInfo>, RoutingError> {
        let config = self.config.read().await;

        let num_guards = match config.security_level {
            super::SecurityLevel::Standard => 1,
            super::SecurityLevel::Enhanced => 2,
            super::SecurityLevel::Maximum => 3,
        };

        let mut guards = Vec::new();

        // Select from first layer
        {
            let first = self.first_layer.read().await;
            if let Some(guard) = self.select_best_guard(&first).await {
                guards.push(guard);
            }
        }

        // Select from second layer (vanguards) for enhanced/maximum security
        if num_guards >= 2 {
            let second = self.second_layer.read().await;
            if let Some(guard) = self.select_best_guard(&second).await {
                guards.push(guard);
            }
        }

        // Select from third layer for maximum security
        if num_guards >= 3 {
            let third = self.third_layer.read().await;
            if let Some(guard) = self.select_best_guard(&third).await {
                guards.push(guard);
            }
        }

        if guards.is_empty() {
            return Err(RoutingError::GuardSelectionFailed(
                "No guards available".to_string(),
            ));
        }

        Ok(guards)
    }

    /// Select best guard from layer
    async fn select_best_guard(&self, layer: &[GuardEntry]) -> Option<GuardInfo> {
        if layer.is_empty() {
            return None;
        }

        let mut rng = rand::thread_rng();

        // Filter out guards with low reputation
        let candidates: Vec<_> = layer.iter().filter(|g| g.reputation > 0.5).collect();

        if candidates.is_empty() {
            return None;
        }

        // Bandwidth-weighted random selection
        let total_bandwidth: u64 = candidates.iter().map(|g| g.info.bandwidth).sum();
        let mut choice = rng.gen_range(0..total_bandwidth);

        for guard in &candidates {
            if choice < guard.info.bandwidth {
                return Some(guard.info.clone());
            }
            choice -= guard.info.bandwidth;
        }

        candidates.choose(&mut rng).map(|g| g.info.clone())
    }

    /// Add guard to layer
    pub async fn add_guard(&self, info: GuardInfo, layer: GuardLayer) -> Result<(), RoutingError> {
        let entry = GuardEntry {
            info,
            added_at: Instant::now(),
            last_used: None,
            use_count: 0,
            failure_count: 0,
            reputation: 1.0,
        };

        match layer {
            GuardLayer::First => {
                let mut guards = self.first_layer.write().await;
                guards.push(entry);
            }
            GuardLayer::Second => {
                let mut guards = self.second_layer.write().await;
                guards.push(entry);
            }
            GuardLayer::Third => {
                let mut guards = self.third_layer.write().await;
                guards.push(entry);
            }
        }

        Ok(())
    }

    /// Rotate guards in layer
    fn rotate_layer(layer: &mut Vec<GuardEntry>, layer_type: GuardLayer) {
        // Remove oldest guards
        let now = Instant::now();
        let max_age = match layer_type {
            GuardLayer::First => Duration::from_secs(90 * 24 * 60 * 60),
            GuardLayer::Second => Duration::from_secs(30 * 24 * 60 * 60),
            GuardLayer::Third => Duration::from_secs(7 * 24 * 60 * 60),
        };

        layer.retain(|g| now.duration_since(g.added_at) < max_age);

        // Remove low-reputation guards
        layer.retain(|g| g.reputation > 0.3);
    }

    /// Report guard failure
    pub async fn report_failure(&self, guard_id: &str) {
        let mut stats = self.usage_stats.write().await;
        if let Some(stat) = stats.get_mut(guard_id) {
            stat.failed_circuits += 1;
        }

        // Update reputation in all layers
        self.update_reputation(guard_id, false).await;
    }

    /// Report guard success
    pub async fn report_success(&self, guard_id: &str, bytes: u64) {
        let mut stats = self.usage_stats.write().await;
        let stat = stats.entry(guard_id.to_string()).or_default();
        stat.total_circuits += 1;
        stat.bytes_transferred += bytes;

        self.update_reputation(guard_id, true).await;
    }

    /// Update guard reputation
    async fn update_reputation(&self, guard_id: &str, success: bool) {
        let update_fn = |layer: &mut Vec<GuardEntry>| {
            for guard in layer.iter_mut() {
                if guard.info.identity == guard_id {
                    if success {
                        guard.reputation = (guard.reputation * 0.9 + 0.1).min(1.0);
                        guard.use_count += 1;
                    } else {
                        guard.reputation *= 0.8;
                        guard.failure_count += 1;
                    }
                }
            }
        };

        update_fn(&mut *self.first_layer.write().await);
        update_fn(&mut *self.second_layer.write().await);
        update_fn(&mut *self.third_layer.write().await);
    }
}

/// Predecessor attack defense
/// Tracks circuit construction patterns to detect predecessor attacks
pub struct PredecessorDefense {
    /// Circuit construction history
    construction_history: Arc<RwLock<VecDeque<CircuitConstruction>>>,
    /// Suspicious pattern threshold
    threshold: f64,
}

/// Circuit construction record
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CircuitConstruction {
    timestamp: Instant,
    first_hop: String,
    second_hop: String,
    third_hop: String,
}

impl PredecessorDefense {
    /// Create new predecessor defense
    pub fn new(threshold: f64) -> Self {
        Self {
            construction_history: Arc::new(RwLock::new(VecDeque::new())),
            threshold,
        }
    }

    /// Record circuit construction
    pub async fn record_construction(&self, first: String, second: String, third: String) {
        let mut history = self.construction_history.write().await;

        history.push_back(CircuitConstruction {
            timestamp: Instant::now(),
            first_hop: first,
            second_hop: second,
            third_hop: third,
        });

        // Keep only last 1000 constructions
        while history.len() > 1000 {
            history.pop_front();
        }
    }

    /// Check for predecessor attack patterns
    pub async fn detect_attack(&self) -> Option<PredecessorAlert> {
        let history = self.construction_history.read().await;

        // Count first hop frequency
        let mut first_hop_counts: HashMap<String, usize> = HashMap::new();
        for construction in history.iter() {
            *first_hop_counts
                .entry(construction.first_hop.clone())
                .or_insert(0) += 1;
        }

        // Check for suspicious concentration
        let total = history.len() as f64;
        for (hop, count) in first_hop_counts {
            let frequency = count as f64 / total;
            if frequency > self.threshold {
                return Some(PredecessorAlert {
                    suspicious_hop: hop,
                    frequency,
                    recommendation: AlertRecommendation::RotateGuard,
                });
            }
        }

        None
    }
}

/// Predecessor attack alert
#[derive(Debug, Clone)]
pub struct PredecessorAlert {
    pub suspicious_hop: String,
    pub frequency: f64,
    pub recommendation: AlertRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertRecommendation {
    RotateGuard,
    BlockGuard,
    Investigate,
}

/// Guard denial-of-service protection
/// Defends against attacks that force guard rotation
pub struct GuardDoSProtection {
    /// DoS detection threshold
    dos_threshold: u64,
    /// Recent connection attempts
    connection_attempts: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    /// Blocked guards
    blocked_guards: Arc<RwLock<HashSet<String>>>,
}

impl GuardDoSProtection {
    /// Create new DoS protection
    pub fn new(dos_threshold: u64) -> Self {
        Self {
            dos_threshold,
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            blocked_guards: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Record connection attempt
    pub async fn record_attempt(&self, guard_id: &str) -> bool {
        let mut attempts = self.connection_attempts.write().await;
        let now = Instant::now();

        let entry = attempts
            .entry(guard_id.to_string())
            .or_insert_with(Vec::new);
        entry.push(now);

        // Remove old attempts (older than 1 minute)
        entry.retain(|t| now.duration_since(*t) < Duration::from_secs(60));

        // Check if threshold exceeded
        if entry.len() as u64 > self.dos_threshold {
            let mut blocked = self.blocked_guards.write().await;
            blocked.insert(guard_id.to_string());
            return false; // Block this attempt
        }

        true // Allow this attempt
    }

    /// Check if guard is blocked
    pub async fn is_blocked(&self, guard_id: &str) -> bool {
        let blocked = self.blocked_guards.read().await;
        blocked.contains(guard_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_guard_manager() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let manager = GuardManager::new(config);

        // Add a guard
        manager
            .add_guard(
                GuardInfo {
                    identity: "guard1".to_string(),
                    address: "192.168.1.1:9001".to_string(),
                    bandwidth: 1000000,
                    layer: GuardLayer::First,
                },
                GuardLayer::First,
            )
            .await
            .unwrap();

        // Should be able to select guards
        let guards = manager.select_guards().await;
        assert!(guards.is_ok());
    }

    #[tokio::test]
    async fn test_predecessor_defense() {
        let defense = PredecessorDefense::new(0.5);

        // Record some constructions
        for _ in 0..10 {
            defense
                .record_construction(
                    "guard1".to_string(),
                    "relay2".to_string(),
                    "relay3".to_string(),
                )
                .await;
        }

        // Should detect concentration
        let alert = defense.detect_attack().await;
        assert!(alert.is_some());
    }
}
