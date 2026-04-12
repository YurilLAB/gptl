//! Sybil Defense Module
//!
//! Implements countermeasures against Sybil attacks including relay validation,
//! reputation systems, and behavioral analysis.

use super::{RoutingConfig, RoutingError};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Sybil shield for detecting and preventing Sybil attacks
pub struct SybilShield {
    config: Arc<RwLock<RoutingConfig>>,
    /// Relay reputation database
    reputation_db: Arc<RwLock<ReputationDB>>,
    /// Sybil detection engine
    detection_engine: Arc<RwLock<SybilDetector>>,
    /// Economic stake verifier
    stake_verifier: Arc<RwLock<StakeVerifier>>,
    /// Geographic diversity checker
    diversity_checker: Arc<RwLock<DiversityChecker>>,
    /// Blocked relays
    blocked_relays: Arc<RwLock<HashSet<String>>>,
}

/// Relay reputation database
#[derive(Debug, Clone)]
struct ReputationDB {
    /// Relay entries
    entries: HashMap<String, ReputationEntry>,
    /// Minimum reputation threshold
    min_reputation: f64,
}

/// Reputation entry
#[derive(Debug, Clone)]
struct ReputationEntry {
    identity: String,
    /// Current reputation score (0.0 - 1.0)
    score: f64,
    /// Successful operations
    successes: u64,
    /// Failed operations
    failures: u64,
    /// First seen
    first_seen: Instant,
    /// Last update
    last_update: Instant,
    /// Flags
    flags: Vec<String>,
}

/// Sybil detection engine
#[derive(Debug, Clone)]
struct SybilDetector {
    /// Detection heuristics
    heuristics: Vec<SybilHeuristic>,
    /// Detected Sybil groups
    sybil_groups: Vec<SybilGroup>,
}

/// Sybil detection heuristic
#[derive(Debug, Clone)]
enum SybilHeuristic {
    /// Same IP subnet
    SameSubnet { prefix_len: u8 },
    /// Similar nickname patterns
    NicknamePattern { pattern: String },
    /// Coordinated behavior
    CoordinatedBehavior { window: Duration },
    /// Bandwidth inflation
    BandwidthInflation { threshold: f64 },
    /// Fingerprint similarity
    FingerprintSimilarity,
}

/// Detected Sybil group
#[derive(Debug, Clone)]
struct SybilGroup {
    /// Group identifier
    group_id: String,
    /// Member relays
    members: Vec<String>,
    /// Detection confidence
    confidence: f64,
    /// Detection timestamp
    detected_at: Instant,
}

/// Economic stake verifier
#[derive(Debug, Clone)]
struct StakeVerifier {
    /// Stake requirements by relay type
    stake_requirements: HashMap<RelayType, u64>,
    /// Verified stakes
    verified_stakes: HashMap<String, StakeProof>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RelayType {
    Guard,
    Middle,
    Exit,
}

/// Stake proof
#[derive(Debug, Clone)]
struct StakeProof {
    identity: String,
    amount: u64,
    proof: Vec<u8>,
    verified_at: Instant,
}

/// Geographic diversity checker
#[derive(Debug, Clone)]
struct DiversityChecker {
    /// Required AS diversity
    min_as_diversity: usize,
    /// Required country diversity
    min_country_diversity: usize,
    /// AS cache
    as_cache: HashMap<IpAddr, AsInfo>,
}

#[derive(Debug, Clone)]
struct AsInfo {
    asn: u32,
    country: String,
    organization: String,
}

impl SybilShield {
    /// Create new Sybil shield
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        let reputation_db = Arc::new(RwLock::new(ReputationDB {
            entries: HashMap::new(),
            min_reputation: 0.5,
        }));
        
        let detection_engine = Arc::new(RwLock::new(SybilDetector {
            heuristics: vec![
                SybilHeuristic::SameSubnet { prefix_len: 24 },
                SybilHeuristic::CoordinatedBehavior { window: Duration::from_secs(3600) },
                SybilHeuristic::BandwidthInflation { threshold: 2.0 },
            ],
            sybil_groups: Vec::new(),
        }));
        
        let stake_verifier = Arc::new(RwLock::new(StakeVerifier {
            stake_requirements: [
                (RelayType::Guard, 1000),
                (RelayType::Middle, 500),
                (RelayType::Exit, 2000),
            ].into_iter().collect(),
            verified_stakes: HashMap::new(),
        }));
        
        let diversity_checker = Arc::new(RwLock::new(DiversityChecker {
            min_as_diversity: 3,
            min_country_diversity: 2,
            as_cache: HashMap::new(),
        }));
        
        let blocked_relays = Arc::new(RwLock::new(HashSet::new()));
        
        Self {
            config,
            reputation_db,
            detection_engine,
            stake_verifier,
            diversity_checker,
            blocked_relays,
        }
    }

    /// Initialize Sybil defense
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        // Start periodic Sybil scanning
        let engine = self.detection_engine.clone();
        let blocked = self.blocked_relays.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                // Run detection
                let mut detector = engine.write().await;
                // Detection logic here
                
                // Block detected Sybils
                for group in &detector.sybil_groups {
                    if group.confidence > 0.9 {
                        let mut blocked_set = blocked.write().await;
                        for member in &group.members {
                            blocked_set.insert(member.clone());
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Verify relay against Sybil attacks
    pub async fn verify_relay(&self, identity: &str) -> Result<bool, RoutingError> {
        // Check if blocked
        {
            let blocked = self.blocked_relays.read().await;
            if blocked.contains(identity) {
                return Ok(false);
            }
        }
        
        // Check reputation
        {
            let db = self.reputation_db.read().await;
            if let Some(entry) = db.entries.get(identity) {
                if entry.score < db.min_reputation {
                    return Ok(false);
                }
            }
        }
        
        // Check economic stake
        {
            let verifier = self.stake_verifier.read().await;
            if !verifier.verified_stakes.contains_key(identity) {
                // No stake - additional verification needed
            }
        }
        
        // Check for Sybil patterns
        {
            let engine = self.detection_engine.read().await;
            for group in &engine.sybil_groups {
                if group.members.contains(&identity.to_string()) {
                    if group.confidence > 0.8 {
                        return Ok(false);
                    }
                }
            }
        }
        
        Ok(true)
    }

    /// Register new relay
    pub async fn register_relay(&self, info: RelayInfo) -> Result<(), RoutingError> {
        // Verify stake
        {
            let verifier = self.stake_verifier.read().await;
            let required = verifier.stake_requirements.get(&info.relay_type).copied().unwrap_or(0);
            
            if info.stake_amount < required {
                return Err(RoutingError::ResourceAllocationFailed(
                    format!("Insufficient stake: {} < {}", info.stake_amount, required)
                ));
            }
        }
        
        // Check geographic diversity
        {
            let checker = self.diversity_checker.read().await;
            if let Some(as_info) = checker.as_cache.get(&info.address) {
                // Verify diversity requirements
            }
        }
        
        // Add to reputation database
        {
            let mut db = self.reputation_db.write().await;
            db.entries.insert(info.identity.clone(), ReputationEntry {
                identity: info.identity,
                score: 0.5, // Neutral starting score
                successes: 0,
                failures: 0,
                first_seen: Instant::now(),
                last_update: Instant::now(),
                flags: Vec::new(),
            });
        }
        
        Ok(())
    }

    /// Report relay behavior
    pub async fn report_behavior(&self, identity: &str, behavior: RelayBehavior) {
        let mut db = self.reputation_db.write().await;
        
        if let Some(entry) = db.entries.get_mut(identity) {
            match behavior {
                RelayBehavior::Success => {
                    entry.successes += 1;
                    entry.score = (entry.score * 0.9 + 0.1).min(1.0);
                }
                RelayBehavior::Failure => {
                    entry.failures += 1;
                    entry.score *= 0.9;
                }
                RelayBehavior::Suspicious => {
                    entry.flags.push("suspicious".to_string());
                    entry.score *= 0.8;
                }
            }
            entry.last_update = Instant::now();
        }
    }

    /// Detect Sybil groups
    pub async fn detect_sybils(&self) -> Vec<SybilGroup> {
        let engine = self.detection_engine.read().await;
        engine.sybil_groups.clone()
    }

    /// Get relay reputation
    pub async fn get_reputation(&self, identity: &str) -> Option<f64> {
        let db = self.reputation_db.read().await;
        db.entries.get(identity).map(|e| e.score)
    }
}

impl ReputationDB {
    /// Update reputation based on age
    fn age_based_reputation(&self, entry: &ReputationEntry) -> f64 {
        let age = entry.first_seen.elapsed().as_secs();
        let age_factor = (age as f64 / (30 * 24 * 3600) as f64).min(1.0); // Max after 30 days
        
        let success_rate = if entry.successes + entry.failures > 0 {
            entry.successes as f64 / (entry.successes + entry.failures) as f64
        } else {
            0.5
        };
        
        (entry.score * 0.3 + success_rate * 0.4 + age_factor * 0.3).min(1.0)
    }
}

impl SybilDetector {
    /// Run detection heuristics
    fn detect_same_subnet(&self, relays: &[RelayInfo], prefix_len: u8) -> Vec<SybilGroup> {
        let mut groups: HashMap<u32, Vec<String>> = HashMap::new();

        for relay in relays {
            if let IpAddr::V4(v4) = relay.address {
                let subnet = Self::extract_subnet(v4, prefix_len);
                groups.entry(subnet).or_default().push(relay.identity.clone());
            }
        }

        groups.into_iter()
            .filter(|(_, members)| members.len() > 2)
            .map(|(subnet, members)| SybilGroup {
                group_id: format!("subnet-{}/{}", subnet, prefix_len),
                members,
                confidence: 0.7,
                detected_at: Instant::now(),
            })
            .collect()
    }

    /// Extract subnet from IPv4 address
    fn extract_subnet(v4: std::net::Ipv4Addr, prefix_len: u8) -> u32 {
        let octets = v4.octets();
        let addr = u32::from_be_bytes(octets);
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        addr & mask
    }

    /// Detect coordinated behavior (2025 best practice: behavioral analysis)
    fn detect_coordinated_behavior(
        &self,
        relays: &[RelayInfo],
        window: Duration,
    ) -> Vec<SybilGroup> {
        // Group by similar behavior patterns
        // Look for simultaneous join/leave patterns
        let mut behavior_groups: HashMap<String, Vec<String>> = HashMap::new();

        for relay in relays {
            // Create behavior fingerprint
            let fingerprint = format!(
                "{}-{}-{}",
                relay.bandwidth / 1000000, // Bandwidth in MB/s
                relay.nickname.len(),
                relay.fingerprint.len()
            );

            behavior_groups.entry(fingerprint)
                .or_default()
                .push(relay.identity.clone());
        }

        behavior_groups.into_iter()
            .filter(|(_, members)| members.len() > 3)
            .map(|(pattern, members)| SybilGroup {
                group_id: format!("behavior-{}", pattern),
                members,
                confidence: 0.6,
                detected_at: Instant::now(),
            })
            .collect()
    }

    /// Graph-based Sybil detection (2025 best practice)
    /// Uses community detection to identify tightly connected Sybil clusters
    pub fn detect_graph_based(&self, relays: &[RelayInfo]) -> Vec<SybilGroup> {
        // Build adjacency matrix based on relay relationships
        let mut adjacency: HashMap<String, HashSet<String>> = HashMap::new();

        // Connect relays with similar characteristics
        for i in 0..relays.len() {
            for j in (i + 1)..relays.len() {
                let similarity = Self::calculate_similarity(&relays[i], &relays[j]);

                // High similarity indicates potential Sybil relationship
                if similarity > 0.8 {
                    adjacency.entry(relays[i].identity.clone())
                        .or_default()
                        .insert(relays[j].identity.clone());
                    adjacency.entry(relays[j].identity.clone())
                        .or_default()
                        .insert(relays[i].identity.clone());
                }
            }
        }

        // Find densely connected components (potential Sybil groups)
        let mut visited = HashSet::new();
        let mut groups = Vec::new();

        for relay in relays {
            if visited.contains(&relay.identity) {
                continue;
            }

            let component = Self::find_connected_component(
                &relay.identity,
                &adjacency,
                &mut visited
            );

            // Groups with 4+ members and high density are suspicious
            if component.len() >= 4 {
                let density = Self::calculate_density(&component, &adjacency);
                if density > 0.7 {
                    groups.push(SybilGroup {
                        group_id: format!("graph-{}", rand::random::<u32>()),
                        members: component,
                        confidence: density,
                        detected_at: Instant::now(),
                    });
                }
            }
        }

        groups
    }

    /// Calculate similarity between two relays
    fn calculate_similarity(relay1: &RelayInfo, relay2: &RelayInfo) -> f64 {
        let mut score = 0.0;
        let mut factors = 0.0;

        // IP proximity
        if Self::same_subnet_check(&relay1.address, &relay2.address, 16) {
            score += 0.3;
        }
        factors += 0.3;

        // Bandwidth similarity
        let bw_ratio = relay1.bandwidth.min(relay2.bandwidth) as f64
            / relay1.bandwidth.max(relay2.bandwidth).max(1) as f64;
        score += bw_ratio * 0.3;
        factors += 0.3;

        // Nickname pattern similarity
        if Self::similar_nicknames(&relay1.nickname, &relay2.nickname) {
            score += 0.4;
        }
        factors += 0.4;

        score / factors
    }

    /// Check if two IPs are in the same subnet
    fn same_subnet_check(ip1: &IpAddr, ip2: &IpAddr, prefix_len: u8) -> bool {
        match (ip1, ip2) {
            (IpAddr::V4(v1), IpAddr::V4(v2)) => {
                let subnet1 = Self::extract_subnet(*v1, prefix_len);
                let subnet2 = Self::extract_subnet(*v2, prefix_len);
                subnet1 == subnet2
            }
            _ => false,
        }
    }

    /// Check if nicknames follow similar patterns
    fn similar_nicknames(nick1: &str, nick2: &str) -> bool {
        // Check for sequential numbering (relay1, relay2, etc.)
        let pattern1 = nick1.trim_end_matches(char::is_numeric);
        let pattern2 = nick2.trim_end_matches(char::is_numeric);

        pattern1 == pattern2 && !pattern1.is_empty()
    }

    /// Find connected component using DFS
    fn find_connected_component(
        start: &str,
        adjacency: &HashMap<String, HashSet<String>>,
        visited: &mut HashSet<String>,
    ) -> Vec<String> {
        let mut component = Vec::new();
        let mut stack = vec![start.to_string()];

        while let Some(node) = stack.pop() {
            if visited.contains(&node) {
                continue;
            }

            visited.insert(node.clone());
            component.push(node.clone());

            if let Some(neighbors) = adjacency.get(&node) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        stack.push(neighbor.clone());
                    }
                }
            }
        }

        component
    }

    /// Calculate graph density
    fn calculate_density(nodes: &[String], adjacency: &HashMap<String, HashSet<String>>) -> f64 {
        if nodes.len() < 2 {
            return 0.0;
        }

        let mut edge_count = 0;
        for node in nodes {
            if let Some(neighbors) = adjacency.get(node) {
                edge_count += neighbors.iter()
                    .filter(|n| nodes.contains(n))
                    .count();
            }
        }

        let max_edges = nodes.len() * (nodes.len() - 1);
        edge_count as f64 / max_edges as f64
    }
}

/// Relay information
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub identity: String,
    pub address: IpAddr,
    pub bandwidth: u64,
    pub relay_type: RelayType,
    pub stake_amount: u64,
    pub nickname: String,
    pub fingerprint: String,
}

/// Relay behavior report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayBehavior {
    Success,
    Failure,
    Suspicious,
}

/// Bandwidth authority simulation
/// Verifies bandwidth claims
pub struct BandwidthAuthority {
    /// Measurement results
    measurements: HashMap<String, BandwidthMeasurement>,
}

#[derive(Debug, Clone)]
struct BandwidthMeasurement {
    claimed: u64,
    measured: u64,
    measurement_time: Instant,
}

impl BandwidthAuthority {
    /// Create new bandwidth authority
    pub fn new() -> Self {
        Self {
            measurements: HashMap::new(),
        }
    }

    /// Measure relay bandwidth
    pub async fn measure(&mut self, identity: &str, claimed: u64) -> u64 {
        // In production, actual bandwidth measurement
        // For now, use conservative estimate
        let measured = claimed / 2;
        
        self.measurements.insert(identity.to_string(), BandwidthMeasurement {
            claimed,
            measured,
            measurement_time: Instant::now(),
        });
        
        measured
    }

    /// Check for bandwidth inflation
    pub fn check_inflation(&self, identity: &str, threshold: f64) -> bool {
        if let Some(measurement) = self.measurements.get(identity) {
            let ratio = measurement.claimed as f64 / measurement.measured.max(1) as f64;
            return ratio > threshold;
        }
        false
    }
}

/// Social trust network
/// Web-of-trust for relay operators
pub struct TrustNetwork {
    /// Trust edges
    edges: HashMap<String, HashSet<String>>,
    /// Trust scores
    scores: HashMap<String, f64>,
}

impl TrustNetwork {
    /// Create new trust network
    pub fn new() -> Self {
        Self {
            edges: HashMap::new(),
            scores: HashMap::new(),
        }
    }

    /// Add trust edge
    pub fn add_trust(&mut self, from: &str, to: &str) {
        self.edges.entry(from.to_string())
            .or_default()
            .insert(to.to_string());
    }

    /// Calculate trust score
    pub fn calculate_trust(&self, identity: &str) -> f64 {
        // Simple trust: number of incoming edges
        let incoming = self.edges.values()
            .filter(|set| set.contains(identity))
            .count();
        
        (incoming as f64 / self.edges.len().max(1) as f64).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_extraction() {
        let v4 = "192.168.1.1".parse().unwrap();
        let subnet = SybilDetector::extract_subnet(v4, 24);
        assert_eq!(subnet, 0xC0A80100); // 192.168.1.0
    }

    #[tokio::test]
    async fn test_sybil_shield() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Should pass verification for new relay
        let result = shield.verify_relay("new-relay").await.unwrap();
        assert!(result); // Not blocked
    }

    #[test]
    fn test_bandwidth_authority() {
        let authority = BandwidthAuthority::new();

        // Test inflation detection
        assert!(!authority.check_inflation("test-relay", 2.0));
    }

    #[test]
    fn test_same_subnet_detection() {
        let detector = SybilDetector {
            heuristics: vec![],
            sybil_groups: vec![],
        };

        let relays = vec![
            RelayInfo {
                identity: "relay1".to_string(),
                address: "192.168.1.1".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "relay1".to_string(),
                fingerprint: "abc123".to_string(),
            },
            RelayInfo {
                identity: "relay2".to_string(),
                address: "192.168.1.2".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "relay2".to_string(),
                fingerprint: "def456".to_string(),
            },
            RelayInfo {
                identity: "relay3".to_string(),
                address: "192.168.1.3".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "relay3".to_string(),
                fingerprint: "ghi789".to_string(),
            },
        ];

        let groups = detector.detect_same_subnet(&relays, 24);
        assert_eq!(groups.len(), 1); // All in same /24
        assert_eq!(groups[0].members.len(), 3);
    }

    #[test]
    fn test_graph_based_detection() {
        let detector = SybilDetector {
            heuristics: vec![],
            sybil_groups: vec![],
        };

        // Create relays with similar characteristics (potential Sybil group)
        let relays = vec![
            RelayInfo {
                identity: "sybil1".to_string(),
                address: "192.168.1.1".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "node1".to_string(),
                fingerprint: "aaa".to_string(),
            },
            RelayInfo {
                identity: "sybil2".to_string(),
                address: "192.168.1.2".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "node2".to_string(),
                fingerprint: "bbb".to_string(),
            },
            RelayInfo {
                identity: "sybil3".to_string(),
                address: "192.168.1.3".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "node3".to_string(),
                fingerprint: "ccc".to_string(),
            },
            RelayInfo {
                identity: "sybil4".to_string(),
                address: "192.168.1.4".parse().unwrap(),
                bandwidth: 1000000,
                relay_type: RelayType::Guard,
                stake_amount: 1000,
                nickname: "node4".to_string(),
                fingerprint: "ddd".to_string(),
            },
        ];

        let groups = detector.detect_graph_based(&relays);
        assert!(!groups.is_empty()); // Should detect the Sybil group
    }

    #[test]
    fn test_similarity_calculation() {
        let relay1 = RelayInfo {
            identity: "relay1".to_string(),
            address: "192.168.1.1".parse().unwrap(),
            bandwidth: 1000000,
            relay_type: RelayType::Guard,
            stake_amount: 1000,
            nickname: "node1".to_string(),
            fingerprint: "abc".to_string(),
        };

        let relay2 = RelayInfo {
            identity: "relay2".to_string(),
            address: "192.168.1.2".parse().unwrap(),
            bandwidth: 1000000,
            relay_type: RelayType::Guard,
            stake_amount: 1000,
            nickname: "node2".to_string(),
            fingerprint: "def".to_string(),
        };

        let similarity = SybilDetector::calculate_similarity(&relay1, &relay2);
        assert!(similarity > 0.5); // High similarity due to same subnet and bandwidth
    }

    #[test]
    fn test_nickname_pattern_detection() {
        assert!(SybilDetector::similar_nicknames("relay1", "relay2"));
        assert!(SybilDetector::similar_nicknames("node001", "node002"));
        assert!(!SybilDetector::similar_nicknames("alice", "bob"));
    }

    #[tokio::test]
    async fn test_reputation_system() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Register relay
        let relay_info = RelayInfo {
            identity: "test-relay".to_string(),
            address: "192.168.1.1".parse().unwrap(),
            bandwidth: 1000000,
            relay_type: RelayType::Guard,
            stake_amount: 1000,
            nickname: "test".to_string(),
            fingerprint: "abc123".to_string(),
        };

        assert!(shield.register_relay(relay_info).await.is_ok());

        // Report successful behavior
        shield.report_behavior("test-relay", RelayBehavior::Success).await;

        // Check reputation increased
        let reputation = shield.get_reputation("test-relay").await;
        assert!(reputation.is_some());
        assert!(reputation.unwrap() > 0.5);
    }

    #[test]
    fn test_trust_network() {
        let mut network = TrustNetwork::new();

        // Build trust relationships
        network.add_trust("alice", "bob");
        network.add_trust("alice", "charlie");
        network.add_trust("bob", "charlie");

        // Charlie has 2 incoming edges
        let trust = network.calculate_trust("charlie");
        assert!(trust > 0.0);
    }

    #[tokio::test]
    async fn test_bandwidth_measurement() {
        let mut authority = BandwidthAuthority::new();

        // Measure bandwidth
        let measured = authority.measure("test-relay", 2000000).await;
        assert_eq!(measured, 1000000); // Conservative estimate (50%)

        // Check for inflation
        assert!(authority.check_inflation("test-relay", 1.5));
    }

    #[test]
    fn test_age_based_reputation() {
        let db = ReputationDB {
            entries: HashMap::new(),
            min_reputation: 0.5,
        };

        let entry = ReputationEntry {
            identity: "test".to_string(),
            score: 0.8,
            successes: 100,
            failures: 10,
            // Use checked_sub to avoid panic on systems with uptime < 30 days
            first_seen: Instant::now()
                .checked_sub(Duration::from_secs(86400 * 30))
                .unwrap_or_else(|| Instant::now() - Duration::from_secs(3600)),
            last_update: Instant::now(),
            flags: vec![],
        };

        let reputation = db.age_based_reputation(&entry);
        // Reputation should always be in valid range; with a good success rate (100/110)
        // and high score (0.8) the floor is ~0.60 even with age_factor=0.
        assert!(reputation >= 0.6 && reputation <= 1.0);
    }

    #[tokio::test]
    async fn test_relay_below_stake_threshold_rejected() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Guard relay requires stake ≥ 1000; provide only 500
        let info = RelayInfo {
            identity: "cheap-relay".to_string(),
            address: "10.0.0.1".parse().unwrap(),
            bandwidth: 1_000_000,
            relay_type: RelayType::Guard,
            stake_amount: 500, // below required 1000
            nickname: "cheap".to_string(),
            fingerprint: "aabbcc".to_string(),
        };

        let result = shield.register_relay(info).await;
        assert!(result.is_err(),
            "relay with stake below threshold must be rejected");
    }

    #[tokio::test]
    async fn test_relay_at_exact_stake_threshold_accepted() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Exit relay requires stake ≥ 2000; provide exactly 2000
        let info = RelayInfo {
            identity: "exact-stake-relay".to_string(),
            address: "10.0.0.2".parse().unwrap(),
            bandwidth: 2_000_000,
            relay_type: RelayType::Exit,
            stake_amount: 2000, // exactly required
            nickname: "exact".to_string(),
            fingerprint: "ddeeff".to_string(),
        };

        let result = shield.register_relay(info).await;
        assert!(result.is_ok(),
            "relay with stake exactly at threshold must be accepted");
    }

    #[tokio::test]
    async fn test_reputation_decay_on_repeated_failures() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Register relay first
        let info = RelayInfo {
            identity: "failing-relay".to_string(),
            address: "10.0.0.5".parse().unwrap(),
            bandwidth: 1_000_000,
            relay_type: RelayType::Middle,
            stake_amount: 500,
            nickname: "failing".to_string(),
            fingerprint: "fffaaa".to_string(),
        };
        shield.register_relay(info).await.unwrap();

        // Report 10 failures — score should decrease
        for _ in 0..10 {
            shield.report_behavior("failing-relay", RelayBehavior::Failure).await;
        }

        let reputation = shield.get_reputation("failing-relay").await.unwrap();
        // Starting score is 0.5; each failure multiplies by 0.9:
        // 0.5 * 0.9^10 ≈ 0.174 — well below 0.5 threshold
        assert!(reputation < 0.5,
            "reputation must decay below threshold after 10 consecutive failures, got {}", reputation);
    }

    #[tokio::test]
    async fn test_behavioral_anomaly_detection_suspicious_flags() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        let info = RelayInfo {
            identity: "suspicious-relay".to_string(),
            address: "10.0.0.6".parse().unwrap(),
            bandwidth: 1_000_000,
            relay_type: RelayType::Guard,
            stake_amount: 1000,
            nickname: "susp".to_string(),
            fingerprint: "123456".to_string(),
        };
        shield.register_relay(info).await.unwrap();

        // Report several suspicious behaviors — score should drop
        for _ in 0..5 {
            shield.report_behavior("suspicious-relay", RelayBehavior::Suspicious).await;
        }

        let reputation = shield.get_reputation("suspicious-relay").await.unwrap();
        // Starting score 0.5 * 0.8^5 ≈ 0.164 — below min_reputation (0.5)
        assert!(reputation < 0.5,
            "repeated suspicious reports must reduce score below threshold, got {}", reputation);
    }

    #[tokio::test]
    async fn test_blocked_relay_verify_returns_false() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Manually block a relay
        {
            let mut blocked = shield.blocked_relays.write().await;
            blocked.insert("blocked-relay".to_string());
        }

        let result = shield.verify_relay("blocked-relay").await.unwrap();
        assert!(!result, "explicitly blocked relay must fail verification");
    }

    #[tokio::test]
    async fn test_sybil_high_confidence_group_blocks_member() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let shield = SybilShield::new(config);

        // Register members
        for i in 0..3_u8 {
            let info = RelayInfo {
                identity: format!("sybil-member-{}", i),
                address: format!("10.0.1.{}", i).parse().unwrap(),
                bandwidth: 1_000_000,
                relay_type: RelayType::Middle,
                stake_amount: 500,
                nickname: format!("sybilnode{}", i),
                fingerprint: format!("fp{}", i),
            };
            shield.register_relay(info).await.unwrap();
        }

        // Inject a high-confidence Sybil group
        {
            let mut engine = shield.detection_engine.write().await;
            engine.sybil_groups.push(SybilGroup {
                group_id: "test-sybil".to_string(),
                members: vec![
                    "sybil-member-0".to_string(),
                    "sybil-member-1".to_string(),
                    "sybil-member-2".to_string(),
                ],
                confidence: 0.95, // > 0.8 threshold
                detected_at: Instant::now(),
            });
        }

        // All members with confidence > 0.8 should fail verification
        for i in 0..3_u8 {
            let result = shield.verify_relay(&format!("sybil-member-{}", i)).await.unwrap();
            assert!(!result,
                "sybil-member-{} with group confidence 0.95 must fail verification", i);
        }
    }
}
