//! BGP Protection Module
//!
//! Implements countermeasures against RAPTOR (Routing Attacks on Privacy in Tor)
//! including BGP hijacking and interception attacks.

use super::{RoutingConfig, RoutingError};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// BGP Guard for protecting against routing attacks
pub struct BgpGuard {
    config: Arc<RwLock<RoutingConfig>>,
    /// RPKI validator
    rpki_validator: Arc<RwLock<RpkiValidator>>,
    /// BGP monitor
    bgp_monitor: Arc<RwLock<BgpMonitor>>,
    /// AS path analyzer
    as_analyzer: Arc<RwLock<AsPathAnalyzer>>,
    /// Known malicious ASes
    malicious_ases: Arc<RwLock<HashSet<u32>>>,
}

/// RPKI validator for route origin validation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RpkiValidator {
    /// ROA (Route Origin Authorization) cache
    roa_cache: HashMap<String, RoaEntry>,
    /// Last update time
    last_update: Instant,
}

/// ROA entry
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RoaEntry {
    prefix: String,
    origin_as: u32,
    max_length: u8,
    valid_until: Instant,
}

/// BGP monitor for real-time anomaly detection
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BgpMonitor {
    /// BGP update history
    update_history: Vec<BgpUpdate>,
    /// Detection heuristics
    heuristics: Vec<DetectionHeuristic>,
}

/// BGP update record
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BgpUpdate {
    timestamp: Instant,
    prefix: String,
    origin_as: u32,
    as_path: Vec<u32>,
}

/// Detection heuristic
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum DetectionHeuristic {
    /// Frequency-based detection
    Frequency { threshold: f64 },
    /// Time-based detection
    Time { threshold: Duration },
    /// Origin validation
    OriginValidation,
    /// Path length anomaly
    PathLength { max_length: usize },
}

/// AS path analyzer
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AsPathAnalyzer {
    /// Historical AS paths
    path_history: HashMap<String, Vec<Vec<u32>>>,
    /// AS relationship database
    as_relationships: HashMap<u32, Vec<u32>>,
}

impl BgpGuard {
    /// Create new BGP guard
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        let rpki_validator = Arc::new(RwLock::new(RpkiValidator {
            roa_cache: HashMap::new(),
            last_update: Instant::now(),
        }));

        let bgp_monitor = Arc::new(RwLock::new(BgpMonitor {
            update_history: Vec::new(),
            heuristics: vec![
                DetectionHeuristic::Frequency { threshold: 0.00001 },
                DetectionHeuristic::Time {
                    threshold: Duration::from_secs(360),
                },
                DetectionHeuristic::OriginValidation,
                DetectionHeuristic::PathLength { max_length: 10 },
            ],
        }));

        let as_analyzer = Arc::new(RwLock::new(AsPathAnalyzer {
            path_history: HashMap::new(),
            as_relationships: HashMap::new(),
        }));

        let malicious_ases = Arc::new(RwLock::new(HashSet::new()));

        Self {
            config,
            rpki_validator,
            bgp_monitor,
            as_analyzer,
            malicious_ases,
        }
    }

    /// Initialize BGP protection
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        // Start BGP monitoring task
        let _monitor = self.bgp_monitor.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                // Check for BGP anomalies
            }
        });

        Ok(())
    }

    /// Check route for BGP threats
    pub async fn check_route(&self, destination: &IpAddr) -> Result<Option<String>, RoutingError> {
        let config = self.config.read().await;

        if !config.bgp_protection {
            return Ok(None);
        }

        // Look up the AS path to the destination (origin AS = last hop).
        let as_path = self.lookup_as_path(destination).await?;

        // RPKI Route Origin Validation (RFC 6811). Only a definitively *Invalid*
        // origin is a threat. NotFound (no covering ROA — the common case for
        // most prefixes) and Valid both pass: rejecting on a cache miss would
        // block essentially all traffic, which is exactly what the previous
        // `validate_prefix` gate did (the ROA cache is empty until fetch_roas
        // runs). A sound Invalid verdict needs the announced origin AS, so this
        // is only evaluated when the AS path is known.
        if let Some(&origin_as) = as_path.last() {
            let rpki = self.rpki_validator.read().await;
            let prefix = format!("{}/32", destination);
            if rpki.validate_route_origin(&prefix, origin_as, 32) == RpkiValidationState::Invalid {
                return Ok(Some("RPKI validation failed (invalid origin)".to_string()));
            }
        }

        // Check for known malicious ASes on the path.
        let malicious = self.malicious_ases.read().await;
        for asn in &as_path {
            if malicious.contains(asn) {
                return Ok(Some(format!("Path contains malicious AS: {}", asn)));
            }
        }
        drop(malicious);

        // Run detection heuristics
        let monitor = self.bgp_monitor.read().await;
        for heuristic in &monitor.heuristics {
            if let Some(alert) = monitor.apply_heuristic(heuristic, destination).await {
                return Ok(Some(alert));
            }
        }

        Ok(None)
    }

    /// Validate AS path diversity
    pub async fn validate_path_diversity(
        &self,
        path1: &[u32],
        path2: &[u32],
    ) -> Result<bool, RoutingError> {
        let _analyzer = self.as_analyzer.read().await;

        // Compare only intermediate hops (exclude first/last which are always shared
        // as the source and destination ASes).
        let middle1 = if path1.len() > 2 {
            &path1[1..path1.len() - 1]
        } else {
            &path1[..0]
        };
        let middle2 = if path2.len() > 2 {
            &path2[1..path2.len() - 1]
        } else {
            &path2[..0]
        };

        let set1: HashSet<_> = middle1.iter().collect();
        let set2: HashSet<_> = middle2.iter().collect();

        let intersection: HashSet<_> = set1.intersection(&set2).collect();

        // Allow at most one common intermediate AS (for IXPs)
        Ok(intersection.len() <= 1)
    }

    /// Lookup AS path for IP
    async fn lookup_as_path(&self, _ip: &IpAddr) -> Result<Vec<u32>, RoutingError> {
        // In production, this would query BGP looking glass or RouteViews
        // For now, return empty path
        Ok(Vec::new())
    }

    /// Report BGP anomaly
    pub async fn report_anomaly(&self, update: BgpUpdate, alert_type: BgpAlertType) {
        let mut monitor = self.bgp_monitor.write().await;
        monitor.update_history.push(update.clone());

        // Take action based on alert type
        match alert_type {
            BgpAlertType::Hijack => {
                // Add origin AS to malicious list
                let mut malicious = self.malicious_ases.write().await;
                malicious.insert(update.origin_as);
            }
            BgpAlertType::Interception => {
                // SECURITY: BGP update details are NOT logged (contain network topology)
                tracing::warn!("BGP interception detected");
            }
            BgpAlertType::Anomaly => {
                // Notify clients to rotate guards
                // SECURITY: Only anomaly type logged, no path details
                tracing::info!("BGP anomaly detected");
            }
        }
    }
}

#[allow(dead_code)]
impl RpkiValidator {
    /// Update ROA cache from RPKI validator
    async fn update_roa_cache(&mut self, entries: Vec<RoaEntry>) {
        for entry in entries {
            self.roa_cache.insert(entry.prefix.clone(), entry);
        }
        self.last_update = Instant::now();
    }

    /// Fetch ROAs from an RPKI validator over the RTR protocol (RFC 8210).
    ///
    /// `validator_url` accepts either `"host:port"` or a bare hostname
    /// (in which case the standard RTR port 8282 is used).  Well-known
    /// public RTR caches:
    ///   * `rtr.rpki.cloudflare.com:8282`
    ///   * `rpki-validator.ripe.net:8323`
    ///   * `rpki.arin.net:8282`
    pub async fn fetch_roas(&mut self, validator_url: &str) -> Result<(), String> {
        use crate::rpki_rtr::{fetch_snapshot, RtrError};
        tracing::info!("RTR fetch_snapshot from {}", validator_url);

        let (host, port) = match validator_url.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(8282)),
            None => (validator_url.to_string(), 8282u16),
        };

        let snapshot = fetch_snapshot(&host, port, Duration::from_secs(60))
            .await
            .map_err(|e: RtrError| format!("RTR fetch from {}: {}", validator_url, e))?;

        tracing::info!(
            "RTR snapshot: session {} serial {} ({} prefixes, version {})",
            snapshot.session_id,
            snapshot.serial,
            snapshot.prefixes.len(),
            snapshot.version,
        );

        // Convert wire-format prefixes into the internal RoaEntry cache.
        // Withdrawal records (announce == false) are ignored on a Reset-
        // Query snapshot — the validator is sending us the complete current
        // state.  Validity window: ROAs are valid until the next refresh
        // (typically 1 hour); cap entries at 24 h so a missed refresh
        // doesn't keep stale routes pinned indefinitely.
        let valid_until = Instant::now() + Duration::from_secs(86400);
        let entries: Vec<RoaEntry> = snapshot
            .prefixes
            .into_iter()
            .filter(|p| p.announce)
            .map(|p| RoaEntry {
                prefix: format!("{}/{}", p.prefix, p.prefix_len),
                origin_as: p.origin_as,
                max_length: p.max_length,
                valid_until,
            })
            .collect();

        self.update_roa_cache(entries).await;
        Ok(())
    }

    /// Validate route origin (ROV - Route Origin Validation)
    pub fn validate_route_origin(
        &self,
        prefix: &str,
        origin_as: u32,
        prefix_len: u8,
    ) -> RpkiValidationState {
        if let Some(roa) = self.roa_cache.get(prefix) {
            if roa.valid_until < Instant::now() {
                return RpkiValidationState::NotFound;
            }

            if roa.origin_as == origin_as && prefix_len <= roa.max_length {
                return RpkiValidationState::Valid;
            } else {
                return RpkiValidationState::Invalid;
            }
        }

        RpkiValidationState::NotFound
    }
}

impl BgpMonitor {
    /// Apply detection heuristic
    async fn apply_heuristic(
        &self,
        heuristic: &DetectionHeuristic,
        destination: &IpAddr,
    ) -> Option<String> {
        match heuristic {
            DetectionHeuristic::Frequency { threshold } => {
                self.check_frequency_anomaly(destination, *threshold).await
            }
            DetectionHeuristic::Time { threshold } => {
                self.check_time_anomaly(destination, *threshold).await
            }
            DetectionHeuristic::OriginValidation => self.check_origin_validation(destination).await,
            DetectionHeuristic::PathLength { max_length } => {
                self.check_path_length(destination, *max_length).await
            }
        }
    }

    /// Check for frequency anomaly
    async fn check_frequency_anomaly(
        &self,
        _destination: &IpAddr,
        threshold: f64,
    ) -> Option<String> {
        // Count announcements per prefix/AS
        let mut frequency_map: HashMap<u32, usize> = HashMap::new();

        for update in &self.update_history {
            *frequency_map.entry(update.origin_as).or_insert(0) += 1;
        }

        let total = self.update_history.len() as f64;

        for (asn, count) in frequency_map {
            let freq = count as f64 / total;
            if freq < threshold {
                return Some(format!(
                    "Low frequency AS detected: {} (freq: {})",
                    asn, freq
                ));
            }
        }

        None
    }

    /// Check for time-based anomaly
    async fn check_time_anomaly(
        &self,
        _destination: &IpAddr,
        threshold: Duration,
    ) -> Option<String> {
        let _now = Instant::now();

        // Group updates by prefix
        let mut prefix_durations: HashMap<String, (Instant, Instant)> = HashMap::new();

        for update in &self.update_history {
            let entry = prefix_durations
                .entry(update.prefix.clone())
                .or_insert((update.timestamp, update.timestamp));
            entry.1 = update.timestamp;
        }

        for (prefix, (start, end)) in prefix_durations {
            let duration = end.duration_since(start);
            if duration < threshold {
                return Some(format!(
                    "Short-lived prefix announcement: {} (duration: {:?})",
                    prefix, duration
                ));
            }
        }

        None
    }

    /// Check origin validation
    async fn check_origin_validation(&self, _destination: &IpAddr) -> Option<String> {
        // In production, validate origin against RPKI/IRR
        None
    }

    /// Check path length anomaly
    async fn check_path_length(&self, _destination: &IpAddr, max_length: usize) -> Option<String> {
        for update in &self.update_history {
            if update.as_path.len() > max_length {
                return Some(format!(
                    "Suspicious AS path length: {} (path: {:?})",
                    update.as_path.len(),
                    update.as_path
                ));
            }
        }

        None
    }
}

/// BGP alert types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpAlertType {
    Hijack,
    Interception,
    Anomaly,
}

/// RPKI validation state (RFC 6811)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkiValidationState {
    /// Route is valid according to RPKI
    Valid,
    /// Route is invalid (wrong origin AS or prefix length)
    Invalid,
    /// No ROA found for this prefix
    NotFound,
}

/// Counter-RAPTOR path selection
pub struct CounterRaptor {
    /// Client location (AS)
    client_as: u32,
    /// Avoid these ASes
    avoid_ases: HashSet<u32>,
}

impl CounterRaptor {
    /// Create new Counter-RAPTOR selector
    pub fn new(client_as: u32) -> Self {
        Self {
            client_as,
            avoid_ases: HashSet::new(),
        }
    }

    /// Select guard with AS awareness
    pub fn select_as_aware_guard(&self, candidates: &[GuardCandidate]) -> Option<GuardCandidate> {
        candidates
            .iter()
            .filter(|g| !self.avoid_ases.contains(&g.asn))
            .filter(|g| g.asn != self.client_as)
            .max_by_key(|g| g.bandwidth)
            .cloned()
    }

    /// Update avoid list based on BGP monitoring
    pub fn update_avoid_list(&mut self, ases: Vec<u32>) {
        self.avoid_ases.extend(ases);
    }
}

/// Guard candidate
#[derive(Debug, Clone)]
pub struct GuardCandidate {
    pub identity: String,
    pub address: String,
    pub bandwidth: u64,
    pub asn: u32,
}

/// ARTEMIS-style real-time detection
pub struct ArtemisDetector {
    /// Detection threshold
    #[allow(dead_code)]
    threshold: f64,
    /// Historical state
    baseline: HashMap<String, BaselineEntry>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BaselineEntry {
    expected_origin: u32,
    expected_path: Vec<u32>,
    confidence: f64,
}

impl ArtemisDetector {
    /// Create new ARTEMIS detector
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            baseline: HashMap::new(),
        }
    }

    /// Detect hijack in real-time
    pub fn detect_hijack(&self, update: &BgpUpdate) -> Option<HijackDetection> {
        if let Some(baseline) = self.baseline.get(&update.prefix) {
            if update.origin_as != baseline.expected_origin {
                return Some(HijackDetection {
                    prefix: update.prefix.clone(),
                    expected_origin: baseline.expected_origin,
                    detected_origin: update.origin_as,
                    confidence: baseline.confidence,
                });
            }
        }

        None
    }
}

/// Hijack detection result
#[derive(Debug, Clone)]
pub struct HijackDetection {
    pub prefix: String,
    pub expected_origin: u32,
    pub detected_origin: u32,
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_check_route_allows_unknown_prefix_by_default() {
        // RFC 6811: a destination with no covering ROA (NotFound) must NOT be
        // rejected. Previously check_route blocked EVERY destination because the
        // ROA cache is empty until fetch_roas runs, breaking all routing whenever
        // bgp_protection was enabled (the default).
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        assert!(
            config.try_read().unwrap().bgp_protection,
            "default has BGP on"
        );
        let guard = BgpGuard::new(config);

        let dest: IpAddr = "93.184.216.34".parse().unwrap(); // example.com
        let threat = guard.check_route(&dest).await.unwrap();
        assert!(
            threat.is_none(),
            "a destination with no ROA must be allowed, got: {:?}",
            threat
        );
    }

    #[tokio::test]
    async fn test_path_diversity() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        let path1 = vec![1, 2, 3, 4];
        let path2 = vec![1, 5, 6, 4];

        // Should allow paths with at most 1 common AS
        let result = guard.validate_path_diversity(&path1, &path2).await.unwrap();
        assert!(result);

        // Test paths with too much overlap
        let path3 = vec![1, 2, 3, 4];
        let path4 = vec![1, 2, 3, 5];
        let result2 = guard.validate_path_diversity(&path3, &path4).await.unwrap();
        assert!(!result2);
    }

    #[test]
    fn test_counter_raptor() {
        let mut counter = CounterRaptor::new(12345);

        let candidates = vec![
            GuardCandidate {
                identity: "guard1".to_string(),
                address: "192.168.1.1:9001".to_string(),
                bandwidth: 1000000,
                asn: 12345, // Same as client
            },
            GuardCandidate {
                identity: "guard2".to_string(),
                address: "192.168.2.1:9001".to_string(),
                bandwidth: 2000000,
                asn: 67890,
            },
        ];

        let selected = counter.select_as_aware_guard(&candidates);
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().asn, 67890); // Should avoid same AS
    }

    #[test]
    fn test_rpki_validation() {
        let mut validator = RpkiValidator {
            roa_cache: HashMap::new(),
            last_update: Instant::now(),
        };

        // Add test ROA
        validator.roa_cache.insert(
            "1.0.0.0/24".to_string(),
            RoaEntry {
                prefix: "1.0.0.0/24".to_string(),
                origin_as: 13335,
                max_length: 24,
                valid_until: Instant::now() + Duration::from_secs(3600),
            },
        );

        // Test valid route
        let state = validator.validate_route_origin("1.0.0.0/24", 13335, 24);
        assert_eq!(state, RpkiValidationState::Valid);

        // Test invalid origin AS
        let state2 = validator.validate_route_origin("1.0.0.0/24", 99999, 24);
        assert_eq!(state2, RpkiValidationState::Invalid);

        // Test not found
        let state3 = validator.validate_route_origin("2.0.0.0/24", 13335, 24);
        assert_eq!(state3, RpkiValidationState::NotFound);
    }

    #[test]
    fn test_artemis_detector() {
        let mut detector = ArtemisDetector::new(0.8);

        // Add baseline
        detector.baseline.insert(
            "1.0.0.0/24".to_string(),
            BaselineEntry {
                expected_origin: 13335,
                expected_path: vec![13335, 174, 3356],
                confidence: 0.95,
            },
        );

        // Test normal announcement
        let update = BgpUpdate {
            timestamp: Instant::now(),
            prefix: "1.0.0.0/24".to_string(),
            origin_as: 13335,
            as_path: vec![13335, 174, 3356],
        };
        assert!(detector.detect_hijack(&update).is_none());

        // Test hijack
        let hijack_update = BgpUpdate {
            timestamp: Instant::now(),
            prefix: "1.0.0.0/24".to_string(),
            origin_as: 99999, // Wrong origin
            as_path: vec![99999, 174, 3356],
        };
        let detection = detector.detect_hijack(&hijack_update);
        assert!(detection.is_some());
        assert_eq!(detection.unwrap().detected_origin, 99999);
    }

    #[tokio::test]
    async fn test_bgp_monitor_heuristics() {
        let monitor = BgpMonitor {
            update_history: vec![BgpUpdate {
                timestamp: Instant::now(),
                prefix: "1.0.0.0/24".to_string(),
                origin_as: 13335,
                as_path: vec![13335, 174],
            }],
            heuristics: vec![DetectionHeuristic::PathLength { max_length: 10 }],
        };

        // Test path length check
        let dest = "1.0.0.0".parse().unwrap();
        let result = monitor.check_path_length(&dest, 10).await;
        assert!(result.is_none()); // Path length 2 is OK
    }

    #[tokio::test]
    async fn test_bgp_guard_initialization() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        assert!(guard.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_malicious_as_blocking() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        // Add malicious AS
        {
            let mut malicious = guard.malicious_ases.write().await;
            malicious.insert(66666);
        }

        // Mock AS path lookup would return the malicious AS
        // In real implementation, check_route would detect it
    }

    #[tokio::test]
    async fn test_path_diversity_identical_paths_fails() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        // Identical intermediate hops → overlap > 1 → must fail diversity check
        let path = vec![1, 2, 3, 4];
        let result = guard.validate_path_diversity(&path, &path).await.unwrap();
        assert!(
            !result,
            "identical paths must fail path diversity (all intermediate hops overlap)"
        );
    }

    #[tokio::test]
    async fn test_path_diversity_single_hop_paths() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        // Paths with 0 or 1 elements have no intermediate hops — diverse by definition
        let short1: Vec<u32> = vec![1];
        let short2: Vec<u32> = vec![2];
        let result = guard
            .validate_path_diversity(&short1, &short2)
            .await
            .unwrap();
        assert!(
            result,
            "single-hop paths have no intermediate hops and must pass diversity check"
        );

        // Two-element paths: only source and destination, also no intermediate hops
        let two1 = vec![1, 4];
        let two2 = vec![1, 5];
        let result2 = guard.validate_path_diversity(&two1, &two2).await.unwrap();
        assert!(
            result2,
            "two-hop paths have no intermediate hops and must pass diversity check"
        );
    }

    #[test]
    fn test_rpki_validation_expired_roa_returns_not_found() {
        let mut validator = RpkiValidator {
            roa_cache: HashMap::new(),
            last_update: Instant::now(),
        };

        // Insert a ROA that is already expired (valid_until in the past).
        // Instant::now().checked_sub(1s) may return None on very short-uptime systems;
        // fall back to Instant::now() in that case — the test still verifies the
        // validator handles a just-expired entry correctly.
        let expired_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        validator.roa_cache.insert(
            "9.9.9.0/24".to_string(),
            RoaEntry {
                prefix: "9.9.9.0/24".to_string(),
                origin_as: 19281,
                max_length: 24,
                valid_until: expired_at,
            },
        );

        let state = validator.validate_route_origin("9.9.9.0/24", 19281, 24);
        // Expired ROA → treated as NotFound
        assert_eq!(
            state,
            RpkiValidationState::NotFound,
            "expired ROA must return NotFound, not Valid"
        );
    }

    #[test]
    fn test_rpki_validation_malformed_asn_zero() {
        let mut validator = RpkiValidator {
            roa_cache: HashMap::new(),
            last_update: Instant::now(),
        };

        // ASN 0 is reserved and should not validate as the expected origin
        validator.roa_cache.insert(
            "10.0.0.0/8".to_string(),
            RoaEntry {
                prefix: "10.0.0.0/8".to_string(),
                origin_as: 64512,
                max_length: 8,
                valid_until: Instant::now() + Duration::from_secs(3600),
            },
        );

        // ASN 0 is not 64512 — must be Invalid
        let state = validator.validate_route_origin("10.0.0.0/8", 0, 8);
        assert_eq!(
            state,
            RpkiValidationState::Invalid,
            "ASN 0 must not satisfy a ROA with a different origin AS"
        );
    }

    #[test]
    fn test_rpki_validation_asn_max_value() {
        // ASN u32::MAX is syntactically valid but should not match a real ROA
        let mut validator = RpkiValidator {
            roa_cache: HashMap::new(),
            last_update: Instant::now(),
        };

        validator.roa_cache.insert(
            "203.0.113.0/24".to_string(),
            RoaEntry {
                prefix: "203.0.113.0/24".to_string(),
                origin_as: 64496,
                max_length: 24,
                valid_until: Instant::now() + Duration::from_secs(3600),
            },
        );

        let state = validator.validate_route_origin("203.0.113.0/24", u32::MAX, 24);
        assert_eq!(
            state,
            RpkiValidationState::Invalid,
            "u32::MAX ASN must not satisfy a different origin ROA"
        );
    }

    #[tokio::test]
    async fn test_path_diversity_many_shared_intermediate_hops_fails() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = BgpGuard::new(config);

        // Both paths share 3 intermediate hops — clearly not diverse
        let path1 = vec![100, 200, 300, 400, 999];
        let path2 = vec![100, 200, 300, 400, 888];
        let result = guard.validate_path_diversity(&path1, &path2).await.unwrap();
        assert!(
            !result,
            "paths sharing 3 intermediate hops must fail diversity check"
        );
    }
}
