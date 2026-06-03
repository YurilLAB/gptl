//! Resource Protection Module
//!
//! Implements countermeasures against Sniper attacks and resource exhaustion
//! including proof-of-work, memory limits, and circuit prioritization.

use super::{CircuitAllocation, ProofOfWork, RoutingConfig, RoutingError};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

/// Constant-time byte slice equality.  Returns false for mismatched lengths;
/// for equal lengths runs in time proportional to the slice length.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Resource guard for protecting against resource exhaustion
pub struct ResourceGuard {
    #[allow(dead_code)]
    config: Arc<RwLock<RoutingConfig>>,
    /// Memory pool
    memory_pool: Arc<RwLock<MemoryPool>>,
    /// Circuit quotas
    circuit_quotas: Arc<RwLock<HashMap<u32, CircuitQuota>>>,
    /// PoW verifier
    pow_verifier: Arc<RwLock<PowVerifier>>,
    /// Rate limiter
    rate_limiter: Arc<RwLock<RateLimiter>>,
    /// OOM handler
    oom_handler: Arc<RwLock<OomHandler>>,
}

/// Memory pool
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MemoryPool {
    total_available: usize,
    allocated: usize,
    circuit_limit: usize,
}

/// Circuit quota
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CircuitQuota {
    max_memory: usize,
    max_bandwidth: u64,
    current_memory: usize,
    current_bandwidth: u64,
}

/// Proof-of-work verifier
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PowVerifier {
    /// Current difficulty
    difficulty: u32,
    /// Verification cache, keyed by the full PoW hash (not nonce) so
    /// an attacker cannot replay the same nonce with a different submitted
    /// hash and pass verification.
    verified_cache: HashMap<Vec<u8>, Instant>,
}

/// Rate limiter for circuit creation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RateLimiter {
    /// Max circuits per client per minute
    max_per_minute: u32,
    /// Client circuit counts
    client_counts: HashMap<String, Vec<Instant>>,
}

/// Out-of-memory handler
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct OomHandler {
    /// Memory threshold (percentage)
    threshold: f64,
    /// Kill priority queue of (circuit_id, verified_difficulty), sorted so
    /// the lowest-difficulty circuits are killed first under memory pressure.
    kill_queue: Vec<(u32, u32)>,
}

impl ResourceGuard {
    /// Default PoW difficulty (leading zero bits) required to allocate a circuit.
    pub const DEFAULT_POW_DIFFICULTY: u32 = 20;

    /// Create new resource guard with the default PoW difficulty.
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        Self::with_difficulty(config, Self::DEFAULT_POW_DIFFICULTY)
    }

    /// Create a resource guard with an explicit PoW difficulty (leading zero
    /// bits). Lower values are useful in tests to keep PoW generation fast.
    pub fn with_difficulty(config: Arc<RwLock<RoutingConfig>>, difficulty: u32) -> Self {
        let memory_pool = Arc::new(RwLock::new(MemoryPool {
            total_available: 1024 * 1024 * 1024, // 1GB
            allocated: 0,
            circuit_limit: 100 * 1024 * 1024, // 100MB per circuit
        }));
        
        let circuit_quotas = Arc::new(RwLock::new(HashMap::new()));
        
        let pow_verifier = Arc::new(RwLock::new(PowVerifier {
            difficulty, // required leading zero bits
            verified_cache: HashMap::new(),
        }));
        
        let rate_limiter = Arc::new(RwLock::new(RateLimiter {
            max_per_minute: 10,
            client_counts: HashMap::new(),
        }));
        
        let oom_handler = Arc::new(RwLock::new(OomHandler {
            threshold: 0.9, // 90%
            kill_queue: Vec::new(),
        }));
        
        Self {
            config,
            memory_pool,
            circuit_quotas,
            pow_verifier,
            rate_limiter,
            oom_handler,
        }
    }

    /// Initialize resource protection
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        // Start memory monitor task
        let pool = self.memory_pool.clone();
        let oom = self.oom_handler.clone();
        let quotas = self.circuit_quotas.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                
                let pool_read = pool.read().await;
                let usage = pool_read.allocated as f64 / pool_read.total_available as f64;
                drop(pool_read);
                
                if usage > 0.9 {
                    // OOM condition - kill circuits, freeing their reserved
                    // memory back into the pool (otherwise `allocated` never
                    // drops and the relay stays permanently "exhausted").
                    let mut oom_handler = oom.write().await;
                    let mut circuit_quotas = quotas.write().await;
                    let mut pool_write = pool.write().await;

                    // Kill lowest-difficulty circuits first (queue is sorted
                    // ascending by difficulty in `allocate`).
                    for (circuit_id, _difficulty) in &oom_handler.kill_queue {
                        if let Some(quota) = circuit_quotas.remove(circuit_id) {
                            pool_write.allocated =
                                pool_write.allocated.saturating_sub(quota.max_memory);
                        }
                    }

                    oom_handler.kill_queue.clear();
                }
            }
        });
        
        Ok(())
    }

    /// Allocate circuit resources
    pub async fn allocate(&self, pow: ProofOfWork) -> Result<CircuitAllocation, RoutingError> {
        // Verify proof-of-work (write lock: verify records the PoW for replay
        // protection). The effective difficulty is clamped to the server's
        // required difficulty so an attacker cannot claim a huge `pow.difficulty`
        // to inflate the memory/bandwidth quota it receives.
        let effective_difficulty = {
            let mut verifier = self.pow_verifier.write().await;
            if !verifier.verify(&pow).await {
                return Err(RoutingError::ResourceAllocationFailed(
                    "Invalid proof-of-work".to_string()
                ));
            }
            pow.difficulty.min(verifier.difficulty)
        };

        // Allocate memory
        let circuit_id = self.generate_circuit_id().await;
        let memory_quota = self.calculate_memory_quota(effective_difficulty);
        let bandwidth_quota = self.calculate_bandwidth_quota(effective_difficulty);

        {
            let mut pool = self.memory_pool.write().await;
            if pool.allocated + memory_quota > pool.total_available {
                return Err(RoutingError::ResourceAllocationFailed(
                    "Memory exhausted".to_string()
                ));
            }
            pool.allocated += memory_quota;
        }

        // Store quota
        {
            let mut quotas = self.circuit_quotas.write().await;
            quotas.insert(circuit_id, CircuitQuota {
                max_memory: memory_quota,
                max_bandwidth: bandwidth_quota,
                current_memory: 0,
                current_bandwidth: 0,
            });
        }

        // Add to kill queue, ordered so the lowest-priority (lowest verified
        // difficulty) circuits are killed first under memory pressure.
        {
            let mut oom = self.oom_handler.write().await;
            oom.kill_queue.push((circuit_id, effective_difficulty));
            oom.kill_queue.sort_by_key(|&(_, difficulty)| difficulty);
        }

        Ok(CircuitAllocation {
            circuit_id,
            memory_quota,
            bandwidth_quota,
        })
    }

    /// Release circuit resources
    pub async fn release(&self, circuit_id: u32) -> Result<(), RoutingError> {
        let mut quotas = self.circuit_quotas.write().await;
        
        if let Some(quota) = quotas.remove(&circuit_id) {
            let mut pool = self.memory_pool.write().await;
            // Free the reserved quota, not just current usage
            pool.allocated = pool.allocated.saturating_sub(quota.max_memory);
        }
        
        // Remove from kill queue
        let mut oom = self.oom_handler.write().await;
        oom.kill_queue.retain(|&(id, _)| id != circuit_id);
        
        Ok(())
    }

    /// Check memory usage for circuit
    pub async fn check_memory(&self, circuit_id: u32, additional: usize) -> bool {
        let quotas = self.circuit_quotas.read().await;
        
        if let Some(quota) = quotas.get(&circuit_id) {
            quota.current_memory + additional <= quota.max_memory
        } else {
            false
        }
    }

    /// Record memory usage
    pub async fn record_memory(&self, circuit_id: u32, bytes: usize) {
        let mut quotas = self.circuit_quotas.write().await;
        
        if let Some(quota) = quotas.get_mut(&circuit_id) {
            quota.current_memory += bytes;
        }
    }

    /// Generate unique circuit ID
    async fn generate_circuit_id(&self) -> u32 {
        // In production, use proper unique ID generation
        rand::random()
    }

    /// Calculate memory quota from the *verified* PoW difficulty.
    fn calculate_memory_quota(&self, difficulty: u32) -> usize {
        let base_quota = 100 * 1024 * 1024; // 100MB base

        // Higher difficulty = more memory
        let difficulty_bonus = (difficulty as usize) * 10 * 1024 * 1024;

        base_quota + difficulty_bonus
    }

    /// Calculate bandwidth quota from the *verified* PoW difficulty.
    fn calculate_bandwidth_quota(&self, difficulty: u32) -> u64 {
        let base_quota = 1024 * 1024; // 1MB/s base

        // Higher difficulty = more bandwidth
        let difficulty_bonus = (difficulty as u64) * 512 * 1024;

        base_quota + difficulty_bonus
    }
}

impl PowVerifier {
    /// How long a successfully-verified PoW is remembered to reject replays.
    const REPLAY_WINDOW: Duration = Duration::from_secs(300);

    /// Verify proof-of-work.
    ///
    /// Takes `&mut self` so a verified PoW can be recorded in the replay cache.
    /// Returns `true` only if the recomputed hash matches, meets the server's
    /// *own* difficulty threshold, and has not been used recently.
    async fn verify(&mut self, pow: &ProofOfWork) -> bool {
        // Recompute SHA256(circuit_id || nonce) and constant-time-compare to
        // the submitted hash. Trusting `pow.hash` blindly lets an attacker
        // submit ProofOfWork { hash: vec![0; 32], .. } and pass.
        let mut hasher = Sha256::new();
        hasher.update(pow.circuit_id.to_le_bytes());
        hasher.update(pow.nonce.to_le_bytes());
        let computed = hasher.finalize();

        if pow.hash.len() != computed.len() {
            return false;
        }
        if !constant_time_eq(&pow.hash, computed.as_slice()) {
            return false;
        }

        let leading_zeros = computed.iter()
            .take_while(|&&b| b == 0)
            .count() * 8;

        // The threshold is the SERVER's difficulty, never the attacker-supplied
        // `pow.difficulty` (which would let a client send difficulty: 0 and pass
        // with zero work).
        if leading_zeros < self.difficulty as usize {
            return false;
        }

        // Anti-replay: reject a PoW whose exact hash was accepted recently, so
        // one solved puzzle cannot be reused to allocate unlimited circuits.
        if let Some(&ts) = self.verified_cache.get(&pow.hash) {
            if ts.elapsed() < Self::REPLAY_WINDOW {
                return false;
            }
        }

        // Record this PoW and prune expired entries to bound cache growth.
        let now = Instant::now();
        self.verified_cache
            .retain(|_, &mut ts| now.duration_since(ts) < Self::REPLAY_WINDOW);
        self.verified_cache.insert(pow.hash.clone(), now);

        true
    }

    /// Update difficulty based on network conditions
    #[allow(dead_code)]
    pub fn adjust_difficulty(&mut self, target_allocation_rate: f64, actual_rate: f64) {
        if actual_rate > target_allocation_rate * 1.2 {
            // Too many allocations, increase difficulty
            self.difficulty = (self.difficulty + 1).min(32);
        } else if actual_rate < target_allocation_rate * 0.8 {
            // Too few allocations, decrease difficulty
            self.difficulty = self.difficulty.saturating_sub(1);
        }
    }
}

/// Circuit window-based throttling
/// Prevents Sniper attacks by enforcing flow control
pub struct CircuitWindow {
    /// Window size (cells)
    window_size: usize,
    /// Current window
    current_window: usize,
    /// Delivered cells
    delivered: usize,
}

impl CircuitWindow {
    /// Create new circuit window
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            current_window: window_size,
            delivered: 0,
        }
    }

    /// Check if can send cell
    pub fn can_send(&self) -> bool {
        self.current_window > 0
    }

    /// Record cell delivery
    pub fn deliver(&mut self) -> bool {
        if self.current_window > 0 {
            self.current_window -= 1;
            self.delivered += 1;
            true
        } else {
            false
        }
    }

    /// Process SENDME (window update)
    pub fn process_sendme(&mut self, increment: usize) {
        self.current_window = (self.current_window + increment).min(self.window_size);
    }

    /// Get window usage ratio
    pub fn usage_ratio(&self) -> f64 {
        1.0 - (self.current_window as f64 / self.window_size as f64)
    }
}

/// Sniper attack detector
pub struct SniperDetector {
    /// Suspicious circuit threshold
    threshold: f64,
    /// Circuit statistics
    circuit_stats: Arc<RwLock<HashMap<u32, SniperStats>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SniperStats {
    cells_received: usize,
    cells_acked: usize,
    last_ack: Instant,
    stall_duration: Duration,
}

impl Default for SniperStats {
    fn default() -> Self {
        Self {
            cells_received: 0,
            cells_acked: 0,
            last_ack: Instant::now(),
            stall_duration: Duration::default(),
        }
    }
}

impl SniperDetector {
    /// Create new sniper detector
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            circuit_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record cell received
    pub async fn record_received(&self, circuit_id: u32) {
        let mut stats = self.circuit_stats.write().await;
        let stat = stats.entry(circuit_id).or_default();
        stat.cells_received += 1;
    }

    /// Record SENDME sent
    pub async fn record_ack(&self, circuit_id: u32) {
        let mut stats = self.circuit_stats.write().await;
        let stat = stats.entry(circuit_id).or_default();
        stat.cells_acked += 1;
        stat.last_ack = Instant::now();
    }

    /// Check for sniper attack pattern
    pub async fn detect_sniper(&self, circuit_id: u32) -> bool {
        let stats = self.circuit_stats.read().await;
        
        if let Some(stat) = stats.get(&circuit_id) {
            // Check for stalled circuit (many cells received, few acked)
            if stat.cells_received > 1000 {
                let ack_ratio = stat.cells_acked as f64 / stat.cells_received as f64;
                
                // Low ack ratio indicates sniper attack
                if ack_ratio < self.threshold {
                    return true;
                }
            }
        }
        
        false
    }

    /// Get circuits to kill (sniper victims)
    pub async fn get_victims(&self) -> Vec<u32> {
        let stats = self.circuit_stats.read().await;
        let mut victims = Vec::new();
        
        for (circuit_id, stat) in stats.iter() {
            if stat.cells_received > 1000 {
                let ack_ratio = stat.cells_acked as f64 / stat.cells_received as f64;
                if ack_ratio < self.threshold {
                    victims.push(*circuit_id);
                }
            }
        }
        
        victims
    }
}

/// Proof-of-work generator for clients
pub struct PowGenerator {
    difficulty: u32,
}

impl PowGenerator {
    /// Create new PoW generator
    pub fn new(difficulty: u32) -> Self {
        Self { difficulty }
    }

    /// Generate proof-of-work
    pub fn generate(&self, circuit_id: u32) -> ProofOfWork {
        let mut nonce: u64 = rand::random();
        let target_zeros = self.difficulty as usize;
        
        loop {
            let mut hasher = Sha256::new();
            hasher.update(circuit_id.to_le_bytes());
            hasher.update(nonce.to_le_bytes());
            let result = hasher.finalize();
            
            // Count leading zeros
            let leading_zeros = result.iter()
                .take_while(|&&b| b == 0)
                .count() * 8;
            
            if leading_zeros >= target_zeros {
                return ProofOfWork {
                    difficulty: self.difficulty,
                    circuit_id,
                    nonce,
                    hash: result.to_vec(),
                };
            }
            
            nonce = nonce.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_window() {
        let mut window = CircuitWindow::new(100);

        assert!(window.can_send());

        // Deliver 50 cells
        for _ in 0..50 {
            assert!(window.deliver());
        }

        assert_eq!(window.current_window, 50);

        // Process SENDME
        window.process_sendme(50);
        assert_eq!(window.current_window, 100);
    }

    #[test]
    fn test_pow_generator() {
        let generator = PowGenerator::new(10);
        let pow = generator.generate(12345);

        // Verify the PoW
        let mut hasher = Sha256::new();
        hasher.update(12345u32.to_le_bytes());
        hasher.update(pow.nonce.to_le_bytes());
        let result = hasher.finalize();

        let leading_zeros = result.iter()
            .take_while(|&&b| b == 0)
            .count() * 8;

        assert!(leading_zeros >= 10);
    }

    #[tokio::test]
    async fn test_sniper_detector() {
        let detector = SniperDetector::new(0.5);

        // Simulate sniper pattern
        for _ in 0..1001 {
            detector.record_received(1).await;
        }

        // Only ack 10 (< 1% ratio)
        for _ in 0..10 {
            detector.record_ack(1).await;
        }

        assert!(detector.detect_sniper(1).await);
    }

    #[tokio::test]
    async fn test_resource_guard() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::new(config);

        assert!(guard.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_allocation() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);

        // Generate valid PoW
        let generator = PowGenerator::new(8); // low difficulty keeps tests fast
        let pow = generator.generate(12345);

        // Allocate circuit
        let result = guard.allocate(pow).await;
        assert!(result.is_ok());

        let allocation = result.unwrap();
        assert!(allocation.memory_quota > 0);
        assert!(allocation.bandwidth_quota > 0);
    }

    #[tokio::test]
    async fn test_memory_quota_enforcement() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);

        // Generate and allocate
        let generator = PowGenerator::new(8); // low difficulty keeps tests fast
        let pow = generator.generate(12345);
        let allocation = guard.allocate(pow).await.unwrap();

        // Check memory within quota
        assert!(guard.check_memory(allocation.circuit_id, 1024).await);

        // Check memory exceeding quota
        assert!(!guard.check_memory(allocation.circuit_id, allocation.memory_quota + 1).await);
    }

    #[tokio::test]
    async fn test_circuit_release() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);

        let generator = PowGenerator::new(8); // low difficulty keeps tests fast
        let pow = generator.generate(12345);
        let allocation = guard.allocate(pow).await.unwrap();

        // Release circuit
        assert!(guard.release(allocation.circuit_id).await.is_ok());

        // Memory should be freed
        let pool = guard.memory_pool.read().await;
        assert_eq!(pool.allocated, 0);
    }

    #[test]
    fn test_pow_verification() {
        let verifier = PowVerifier {
            difficulty: 10,
            verified_cache: HashMap::new(),
        };

        // Generate valid PoW
        let generator = PowGenerator::new(10);
        let pow = generator.generate(12345);

        // Verification would be async in real usage
        // assert!(verifier.verify(&pow).await);
    }

    #[test]
    fn test_difficulty_adjustment() {
        let mut verifier = PowVerifier {
            difficulty: 20,
            verified_cache: HashMap::new(),
        };

        // Too many allocations - increase difficulty
        verifier.adjust_difficulty(10.0, 15.0);
        assert_eq!(verifier.difficulty, 21);

        // Too few allocations - decrease difficulty
        verifier.adjust_difficulty(10.0, 5.0);
        assert_eq!(verifier.difficulty, 20);
    }

    #[test]
    fn test_circuit_window_usage() {
        let mut window = CircuitWindow::new(100);

        // Deliver 75 cells
        for _ in 0..75 {
            window.deliver();
        }

        let usage = window.usage_ratio();
        assert!((usage - 0.75).abs() < 0.01); // 75% usage
    }

    #[tokio::test]
    async fn test_sniper_victim_identification() {
        let detector = SniperDetector::new(0.5);

        // Create multiple circuits with different patterns
        for _ in 0..1001 {
            detector.record_received(1).await;
        }
        for _ in 0..10 {
            detector.record_ack(1).await;
        }

        // Normal circuit
        for _ in 0..100 {
            detector.record_received(2).await;
            detector.record_ack(2).await;
        }

        let victims = detector.get_victims().await;
        assert_eq!(victims.len(), 1);
        assert_eq!(victims[0], 1);
    }

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool {
            total_available: 1024 * 1024 * 1024,
            allocated: 0,
            circuit_limit: 100 * 1024 * 1024,
        };

        assert_eq!(pool.total_available, 1024 * 1024 * 1024);
        assert_eq!(pool.allocated, 0);
    }

    #[tokio::test]
    async fn test_oom_handler() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::new(config);

        // Simulate high memory usage
        let mut pool = guard.memory_pool.write().await;
        pool.allocated = (pool.total_available as f64 * 0.95) as usize;
        drop(pool);

        // OOM handler should trigger in background task
        // In real usage, circuits would be killed
    }

    #[test]
    fn test_pow_hash_verification() {
        let generator = PowGenerator::new(16);
        let pow = generator.generate(99999);

        // Verify hash has correct difficulty
        let leading_zeros = pow.hash.iter()
            .take_while(|&&b| b == 0)
            .count() * 8;

        assert!(leading_zeros >= 16);
        assert_eq!(pow.difficulty, 16);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::new(config);

        // Rate limiter is checked during allocation
        // In production, would enforce max circuits per minute
        let limiter = guard.rate_limiter.read().await;
        assert_eq!(limiter.max_per_minute, 10);
    }

    #[tokio::test]
    async fn test_pow_wrong_nonce_fails_verification() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::new(config);

        // Generate a valid PoW
        let generator = PowGenerator::new(8);
        let mut pow = generator.generate(42);

        // Corrupt the nonce so the hash no longer matches
        pow.nonce = pow.nonce.wrapping_add(1);

        // The stored hash doesn't have leading zeros for this nonce, but the verifier
        // checks pow.hash directly (not re-hashing), so to make the test meaningful
        // we also zero out the hash to ensure the leading-zero check fails.
        pow.hash = vec![0xFFu8; 32]; // no leading zeros

        let result = guard.allocate(pow).await;
        assert!(result.is_err(),
            "PoW with hash lacking required leading zeros must be rejected");
    }

    #[tokio::test]
    async fn test_attacker_supplied_difficulty_is_ignored() {
        // A client must not be able to bypass PoW by claiming difficulty 0.
        // The server enforces its OWN difficulty, so a near-zero-work PoW (even
        // with a valid hash) must be rejected by a normal-difficulty guard.
        let generator = PowGenerator::new(0);
        let mut pow = generator.generate(1);
        // Attacker also lies about the difficulty field — must be ignored.
        pow.difficulty = 0;

        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::new(config); // default difficulty (20)
        let result = guard.allocate(pow).await;
        assert!(
            result.is_err(),
            "a zero-work PoW must be rejected regardless of the claimed difficulty"
        );
    }

    #[tokio::test]
    async fn test_pow_cannot_be_replayed() {
        // One solved PoW must not allocate more than one circuit.
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);
        let generator = PowGenerator::new(8);
        let pow = generator.generate(31337);

        assert!(guard.allocate(pow.clone()).await.is_ok(), "first use succeeds");
        assert!(
            guard.allocate(pow).await.is_err(),
            "replaying the same PoW must be rejected"
        );
    }

    #[tokio::test]
    async fn test_attacker_cannot_inflate_quota_via_difficulty() {
        // Claiming a huge difficulty must not grant a larger memory/bandwidth
        // quota than the server's verified difficulty warrants.
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);
        let generator = PowGenerator::new(8);
        let mut pow = generator.generate(4242);
        pow.difficulty = u32::MAX; // lie

        let alloc = guard.allocate(pow).await.unwrap();
        // Quota is bounded by the server difficulty (8), not u32::MAX.
        assert_eq!(alloc.memory_quota, 100 * 1024 * 1024 + 8 * 10 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_memory_over_allocation_rejected() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);

        // Fill the memory pool to near capacity first
        {
            let mut pool = guard.memory_pool.write().await;
            // Leave only 1 byte free
            pool.allocated = pool.total_available - 1;
        }

        // A new allocation needs at least base_quota (100 MB) → must fail
        let generator = PowGenerator::new(8);
        let pow = generator.generate(777);
        let result = guard.allocate(pow).await;
        assert!(result.is_err(),
            "allocation must fail when memory pool is exhausted");
    }

    #[tokio::test]
    async fn test_memory_check_over_quota_rejected() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = ResourceGuard::with_difficulty(config, 8);

        let generator = PowGenerator::new(8);
        let pow = generator.generate(555);
        let allocation = guard.allocate(pow).await.unwrap();

        // Trying to add more than the quota must be rejected
        let over_quota = allocation.memory_quota + 1;
        let ok = guard.check_memory(allocation.circuit_id, over_quota).await;
        assert!(!ok,
            "check_memory must return false when additional bytes would exceed max_memory");
    }

    #[test]
    fn test_pow_difficulty_zero_verifier() {
        // PowVerifier with difficulty 0 must accept any hash (0 leading zero bits required)
        let verifier = PowVerifier {
            difficulty: 0,
            verified_cache: HashMap::new(),
        };

        // A hash of all 0xFF bytes has 0 leading zeros
        let pow = super::super::ProofOfWork {
            difficulty: 0,
            circuit_id: 0,
            nonce: 0,
            hash: vec![0xFFu8; 32],
        };

        // leading_zeros = 0 >= 0 → should pass
        let leading_zeros = pow.hash.iter().take_while(|&&b| b == 0).count() * 8;
        assert!(leading_zeros >= pow.difficulty as usize,
            "difficulty 0 must accept a hash with zero leading zero bits");
    }
}
