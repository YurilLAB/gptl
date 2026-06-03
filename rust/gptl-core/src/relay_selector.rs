//! Relay Selector Module
//!
//! Provides intelligent relay selection strategies:
//! - Random selection from healthy pool
//! - Weighted selection by bandwidth or latency
//! - Geographic proximity selection
//! - Security level filtering
//! - Exclusion of recently failed relays

use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, trace, warn};

use crate::relay_registry::{HealthStatus, RelayCriteria, RelayInfo, RelayRegistry, SecurityLevel};

/// Selection strategy for choosing relays
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SelectionStrategy {
    /// Pure random selection from matching relays
    Random,
    /// Weighted by bandwidth (higher bandwidth = higher probability)
    BandwidthWeighted,
    /// Weighted by latency (lower latency = higher probability)
    LatencyWeighted,
    /// Geographic proximity to client
    Geographic,
    /// Hybrid: combine bandwidth and health score
    #[default]
    Hybrid,
}

/// Relay score for ranking
#[derive(Debug, Clone)]
struct RelayScore {
    relay: RelayInfo,
    score: f64,
    #[allow(dead_code)]
    bandwidth_weight: f64,
    #[allow(dead_code)]
    latency_weight: f64,
    #[allow(dead_code)]
    health_weight: f64,
    #[allow(dead_code)]
    geographic_weight: f64,
}

/// Recent failure tracking
#[derive(Debug, Clone)]
struct FailureRecord {
    timestamp: Instant,
    failure_type: FailureType,
    retry_count: u32,
}

/// Types of failures that can occur when connecting to relays
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureType {
    /// Connection failed (timeout or refused)
    ConnectionFailed,
    /// Operation timeout
    Timeout,
    /// Protocol error (invalid messages)
    ProtocolError,
    /// Authentication failure
    AuthenticationFailed,
    /// Relay explicitly rejected connection
    RelayRejected,
}

/// Relay selector for intelligent relay selection
pub struct RelaySelector<R: RelayRegistry> {
    /// Underlying registry
    registry: Arc<R>,
    /// Selection strategy
    strategy: SelectionStrategy,
    /// Recent failures (relay_id -> failure record)
    recent_failures: Arc<RwLock<HashMap<String, FailureRecord>>>,
    /// Circuit attempts per relay (for load balancing)
    circuit_counts: Arc<RwLock<HashMap<String, u64>>>,
    /// Minimum time before retrying a failed relay
    retry_cooldown: Duration,
    /// Maximum retry attempts
    max_retries: u32,
    /// Default criteria
    default_criteria: RelayCriteria,
    /// Geographic preference (client location)
    client_location: Option<crate::relay_registry::Location>,
    /// Selection history for avoiding repetition
    selection_history: Arc<RwLock<VecDeque<String>>>,
    /// History size limit
    history_limit: usize,
}

use std::collections::VecDeque;

/// Selection result
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Selected relay
    pub relay: RelayInfo,
    /// Selection strategy used
    pub strategy: SelectionStrategy,
    /// Score if weighted selection was used
    pub score: Option<f64>,
    /// Estimated latency (if available)
    pub estimated_latency: Option<Duration>,
}

/// Selector configuration
#[derive(Debug, Clone)]
pub struct SelectorConfig {
    /// Selection strategy
    pub strategy: SelectionStrategy,
    /// Retry cooldown duration
    pub retry_cooldown: Duration,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Minimum bandwidth requirement (bytes/sec)
    pub min_bandwidth: Option<u64>,
    /// Required security level
    pub min_security_level: Option<SecurityLevel>,
    /// History limit for avoiding repetition
    pub history_limit: usize,
    /// Client geographic location
    pub client_location: Option<crate::relay_registry::Location>,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self {
            strategy: SelectionStrategy::default(),
            retry_cooldown: Duration::from_secs(300), // 5 minutes
            max_retries: 3,
            min_bandwidth: Some(1024 * 1024), // 1 MB/s minimum
            min_security_level: Some(SecurityLevel::Enhanced),
            history_limit: 10,
            client_location: None,
        }
    }
}

impl<R: RelayRegistry> RelaySelector<R> {
    /// Borrow the underlying registry — used by pool-aware callers that
    /// need to re-check the health of a cached relay ID before reusing it.
    pub fn registry(&self) -> &Arc<R> {
        &self.registry
    }

    /// Currently configured selection strategy.
    pub fn strategy(&self) -> SelectionStrategy {
        self.strategy
    }

    /// Create a new relay selector
    pub fn new(registry: Arc<R>) -> Self {
        Self::with_config(registry, SelectorConfig::default())
    }

    /// Create with configuration
    pub fn with_config(registry: Arc<R>, config: SelectorConfig) -> Self {
        let default_criteria = RelayCriteria::new()
            .with_min_bandwidth(config.min_bandwidth.unwrap_or(0))
            .with_min_security_level(config.min_security_level.unwrap_or(SecurityLevel::Standard))
            .require_healthy();

        Self {
            registry,
            strategy: config.strategy,
            recent_failures: Arc::new(RwLock::new(HashMap::new())),
            circuit_counts: Arc::new(RwLock::new(HashMap::new())),
            retry_cooldown: config.retry_cooldown,
            max_retries: config.max_retries,
            default_criteria,
            client_location: config.client_location,
            selection_history: Arc::new(RwLock::new(VecDeque::new())),
            history_limit: config.history_limit,
        }
    }

    /// Select a single relay
    pub async fn select(&self) -> Result<SelectionResult, SelectorError> {
        self.select_with_criteria(&self.default_criteria.clone())
            .await
    }

    /// Select with custom criteria
    pub async fn select_with_criteria(
        &self,
        criteria: &RelayCriteria,
    ) -> Result<SelectionResult, SelectorError> {
        // Get matching relays
        let mut relays = self
            .registry
            .list_matching(criteria)
            .await
            .map_err(|e| SelectorError::RegistryError(e.to_string()))?;

        if relays.is_empty() {
            warn!("No relays match the specified criteria");
            return Err(SelectorError::NoRelaysAvailable);
        }

        // Filter out recently failed relays
        relays = self.filter_recent_failures(relays).await;

        if relays.is_empty() {
            warn!("All matching relays have recent failures");
            // Try to include failed relays as last resort
            relays = self
                .registry
                .list_matching(criteria)
                .await
                .map_err(|e| SelectorError::RegistryError(e.to_string()))?;

            if relays.is_empty() {
                return Err(SelectorError::NoRelaysAvailable);
            }
        }

        // Exclude recently selected relays from history
        relays = self.exclude_from_history(relays).await;

        if relays.is_empty() {
            // Clear history and try again
            {
                let mut history = self.selection_history.write().await;
                history.clear();
            }
            relays = self
                .registry
                .list_matching(criteria)
                .await
                .map_err(|e| SelectorError::RegistryError(e.to_string()))?;
            relays = self.filter_recent_failures(relays).await;
        }

        // Select based on strategy
        let result = match self.strategy {
            SelectionStrategy::Random => self.select_random(&relays).await,
            SelectionStrategy::BandwidthWeighted => self.select_bandwidth_weighted(&relays).await,
            SelectionStrategy::LatencyWeighted => self.select_latency_weighted(&relays).await,
            SelectionStrategy::Geographic => self.select_geographic(&relays).await,
            SelectionStrategy::Hybrid => self.select_hybrid(&relays).await,
        };

        // Update selection history
        if let Ok(ref selection) = result {
            self.update_history(selection.relay.id.clone()).await;

            // Update circuit count
            let mut counts = self.circuit_counts.write().await;
            *counts.entry(selection.relay.id.clone()).or_insert(0) += 1;
        }

        result
    }

    /// Select multiple relays for multi-hop circuits
    pub async fn select_multiple(
        &self,
        count: usize,
        exclude_same_region: bool,
    ) -> Result<Vec<SelectionResult>, SelectorError> {
        let mut results = Vec::with_capacity(count);
        let mut excluded_regions = HashSet::new();
        let mut excluded_ids = Vec::new();

        for i in 0..count {
            let mut criteria = self.default_criteria.clone();
            criteria.excluded_ids = excluded_ids.clone();

            // Exclude the country codes already used by previous hops so the
            // path spans multiple jurisdictions (previously this block was a
            // no-op, so all hops could land in the same region).
            if exclude_same_region && i > 0 {
                criteria.excluded_regions = excluded_regions.iter().cloned().collect();
            }

            match self.select_with_criteria(&criteria).await {
                Ok(selection) => {
                    if let Some(ref code) = selection.relay.location.country_code {
                        excluded_regions.insert(code.clone());
                    }
                    excluded_ids.push(selection.relay.id.clone());
                    results.push(selection);
                }
                Err(e) => {
                    warn!("Failed to select relay {}: {}", i, e);
                    return Err(e);
                }
            }
        }

        Ok(results)
    }

    /// Report a relay failure
    pub async fn report_failure(&self, relay_id: &str, failure_type: FailureType) {
        let mut failures = self.recent_failures.write().await;

        let record = failures
            .entry(relay_id.to_string())
            .or_insert(FailureRecord {
                timestamp: Instant::now(),
                failure_type: FailureType::ConnectionFailed,
                retry_count: 0,
            });

        record.timestamp = Instant::now();
        record.failure_type = failure_type;
        record.retry_count += 1;

        // Update health status in registry if too many failures
        if record.retry_count >= self.max_retries {
            if let Err(e) = self
                .registry
                .update_health(relay_id, HealthStatus::Degraded)
                .await
            {
                warn!("Failed to update health status for {}: {}", relay_id, e);
            }
        }

        warn!(
            "Relay {} reported failure (type: {:?}, retries: {})",
            relay_id, failure_type, record.retry_count
        );
    }

    /// Report a successful connection
    pub async fn report_success(&self, relay_id: &str) {
        let mut failures = self.recent_failures.write().await;

        if let Some(record) = failures.get_mut(relay_id) {
            // Check before resetting — restore health if relay was previously degraded
            if record.retry_count >= self.max_retries {
                if let Err(e) = self
                    .registry
                    .update_health(relay_id, HealthStatus::Healthy)
                    .await
                {
                    warn!("Failed to update health status for {}: {}", relay_id, e);
                }
            }
            record.retry_count = 0;
        }

        // Update last seen
        if let Err(e) = self.registry.update_last_seen(relay_id).await {
            trace!("Failed to update last_seen for {}: {}", relay_id, e);
        }
    }

    /// Get selection statistics
    pub async fn get_statistics(&self) -> SelectorStatistics {
        let failures = self.recent_failures.read().await;
        let circuits = self.circuit_counts.read().await;

        SelectorStatistics {
            recent_failures: failures.len(),
            total_circuits: circuits.values().sum(),
            circuits_per_relay: circuits.clone(),
        }
    }

    /// Clear failure records
    pub async fn clear_failures(&self) {
        let mut failures = self.recent_failures.write().await;
        failures.clear();
    }

    /// Set selection strategy
    pub fn set_strategy(&mut self, strategy: SelectionStrategy) {
        self.strategy = strategy;
    }

    /// Update default criteria
    pub fn set_default_criteria(&mut self, criteria: RelayCriteria) {
        self.default_criteria = criteria;
    }

    /// Filter out recently failed relays
    async fn filter_recent_failures(&self, relays: Vec<RelayInfo>) -> Vec<RelayInfo> {
        let failures = self.recent_failures.read().await;
        let now = Instant::now();

        relays
            .into_iter()
            .filter(|relay| {
                if let Some(record) = failures.get(&relay.id) {
                    // Back off for `retry_cooldown`, scaled by the number of
                    // consecutive failures (so flakier relays wait longer) but
                    // capped at `max_retries` multiples. Crucially the penalty is
                    // BOUNDED: once it elapses the relay is eligible again. The
                    // old code excluded any relay at >= max_retries forever, and
                    // since retry_count is only reset by a success that requires
                    // re-selection, such relays were permanently removed —
                    // steadily starving the usable pool.
                    let multiplier = record.retry_count.clamp(1, self.max_retries);
                    let penalty = self.retry_cooldown.saturating_mul(multiplier);
                    if now.duration_since(record.timestamp) < penalty {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Exclude recently selected relays from history
    async fn exclude_from_history(&self, relays: Vec<RelayInfo>) -> Vec<RelayInfo> {
        let history = self.selection_history.read().await;
        let history_set: HashSet<_> = history.iter().cloned().collect();

        let filtered: Vec<_> = relays
            .iter()
            .filter(|r| !history_set.contains(&r.id))
            .cloned()
            .collect();

        if filtered.is_empty() {
            // Return all if history excludes everything
            drop(history);
            relays
        } else {
            filtered
        }
    }

    /// Update selection history
    async fn update_history(&self, relay_id: String) {
        let mut history = self.selection_history.write().await;
        history.push_back(relay_id);

        while history.len() > self.history_limit {
            history.pop_front();
        }
    }

    /// Random selection
    async fn select_random(&self, relays: &[RelayInfo]) -> Result<SelectionResult, SelectorError> {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // Create a new RNG with a random seed for Send safety
        let seed = rand::random::<u64>();
        let mut rng = StdRng::seed_from_u64(seed);

        relays
            .choose(&mut rng)
            .cloned()
            .map(|relay| SelectionResult {
                relay,
                strategy: SelectionStrategy::Random,
                score: None,
                estimated_latency: None,
            })
            .ok_or(SelectorError::NoRelaysAvailable)
    }

    /// Bandwidth-weighted selection
    async fn select_bandwidth_weighted(
        &self,
        relays: &[RelayInfo],
    ) -> Result<SelectionResult, SelectorError> {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = rand::random::<u64>();
        let mut rng = StdRng::seed_from_u64(seed);

        let total_bandwidth: u64 = relays.iter().map(|r| r.bandwidth).sum();
        if total_bandwidth == 0 {
            return self.select_random(relays).await;
        }

        let mut choice = rng.gen_range(0..total_bandwidth);

        for relay in relays {
            if choice < relay.bandwidth {
                let score = relay.bandwidth as f64 / total_bandwidth as f64;
                return Ok(SelectionResult {
                    relay: relay.clone(),
                    strategy: SelectionStrategy::BandwidthWeighted,
                    score: Some(score),
                    estimated_latency: None,
                });
            }
            choice -= relay.bandwidth;
        }

        // Fallback to last relay
        relays
            .last()
            .cloned()
            .map(|relay| SelectionResult {
                relay,
                strategy: SelectionStrategy::BandwidthWeighted,
                score: Some(0.0),
                estimated_latency: None,
            })
            .ok_or(SelectorError::NoRelaysAvailable)
    }

    /// Select using bandwidth-as-latency heuristic (lower bandwidth = higher estimated latency)
    async fn select_latency_weighted(
        &self,
        relays: &[RelayInfo],
    ) -> Result<SelectionResult, SelectorError> {
        // Bandwidth-as-latency proxy: higher bandwidth implies lower latency.
        // Synthetic estimate: latency_ms = 50 + (1_000_000 / (bandwidth + 1))
        let scored: Vec<_> = relays
            .iter()
            .map(|r| {
                let latency_ms = 50 + (1_000_000.0 / (r.bandwidth as f64 + 1.0)) as u64;
                // Selection probability is inverse of estimated latency (prefer low-latency)
                let score = 1.0 / latency_ms as f64;
                RelayScore {
                    relay: r.clone(),
                    score,
                    bandwidth_weight: r.bandwidth as f64,
                    latency_weight: score,
                    health_weight: if r.health_status == HealthStatus::Healthy {
                        1.0
                    } else {
                        0.5
                    },
                    geographic_weight: 1.0,
                }
            })
            .collect();

        let total_score: f64 = scored.iter().map(|s| s.score).sum();
        // Use a block to drop rng before any await points
        let winner = {
            let mut rng = rand::thread_rng();
            let mut choice = rng.gen_range(0.0..total_score);
            let mut found: Option<(RelayScore, u64)> = None;
            for score in scored {
                let latency_ms = 50 + (1_000_000.0 / (score.relay.bandwidth as f64 + 1.0)) as u64;
                if choice < score.score {
                    found = Some((score, latency_ms));
                    break;
                }
                choice -= score.score;
            }
            found
        };

        if let Some((score, latency_ms)) = winner {
            return Ok(SelectionResult {
                relay: score.relay,
                strategy: SelectionStrategy::LatencyWeighted,
                score: Some(score.score / total_score),
                estimated_latency: Some(Duration::from_millis(latency_ms)),
            });
        }

        self.select_random(relays).await
    }

    /// Geographic selection
    async fn select_geographic(
        &self,
        relays: &[RelayInfo],
    ) -> Result<SelectionResult, SelectorError> {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        // If we don't have client location, fall back to random
        let client_loc = match &self.client_location {
            Some(loc) => loc,
            None => return self.select_random(relays).await,
        };

        // Score by geographic proximity
        let scored: Vec<_> = relays
            .iter()
            .map(|r| {
                let distance = calculate_distance(client_loc, &r.location);
                // Convert distance to score (closer = higher score)
                let score = 1.0 / (1.0 + distance / 1000.0);

                RelayScore {
                    relay: r.clone(),
                    score,
                    bandwidth_weight: r.bandwidth as f64,
                    latency_weight: 1.0,
                    health_weight: 1.0,
                    geographic_weight: score,
                }
            })
            .collect();

        let seed = rand::random::<u64>();
        let mut rng = StdRng::seed_from_u64(seed);
        let total_score: f64 = scored.iter().map(|s| s.score).sum();
        let mut choice = rng.gen_range(0.0..total_score);

        for score in scored {
            if choice < score.score {
                return Ok(SelectionResult {
                    relay: score.relay,
                    strategy: SelectionStrategy::Geographic,
                    score: Some(score.score / total_score),
                    estimated_latency: Some(Duration::from_millis(
                        (score.geographic_weight * 100.0) as u64,
                    )),
                });
            }
            choice -= score.score;
        }

        self.select_random(relays).await
    }

    /// Hybrid selection combining multiple factors
    async fn select_hybrid(&self, relays: &[RelayInfo]) -> Result<SelectionResult, SelectorError> {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = rand::random::<u64>();
        let mut rng = StdRng::seed_from_u64(seed);

        // Calculate normalized scores
        let max_bandwidth = relays.iter().map(|r| r.bandwidth).max().unwrap_or(1) as f64;

        let scored: Vec<_> = relays
            .iter()
            .map(|r| {
                // Bandwidth score (0-1)
                let bw_score = r.bandwidth as f64 / max_bandwidth;

                // Health score (0-1)
                let health_score = match r.health_status {
                    HealthStatus::Healthy => 1.0,
                    HealthStatus::Degraded => 0.7,
                    _ => 0.0,
                };

                // Age score (prefer relays seen recently)
                let age_score = if let Ok(age) = SystemTime::now().duration_since(r.last_seen) {
                    let hours = age.as_secs() as f64 / 3600.0;
                    1.0 / (1.0 + hours / 24.0) // Decay over days
                } else {
                    0.0
                };

                // Geographic score if location available
                let geo_score = if let Some(ref client_loc) = self.client_location {
                    let distance = calculate_distance(client_loc, &r.location);
                    1.0 / (1.0 + distance / 1000.0)
                } else {
                    0.5 // Neutral if no location
                };

                // Combined score with weights
                let score = bw_score * 0.4 + health_score * 0.3 + age_score * 0.2 + geo_score * 0.1;

                RelayScore {
                    relay: r.clone(),
                    score,
                    bandwidth_weight: bw_score,
                    latency_weight: age_score,
                    health_weight: health_score,
                    geographic_weight: geo_score,
                }
            })
            .collect();

        // Weighted random selection
        let total_score: f64 = scored.iter().map(|s| s.score).sum();
        if total_score == 0.0 {
            return self.select_random(relays).await;
        }

        let mut choice = rng.gen_range(0.0..total_score);

        for score in scored {
            if choice < score.score {
                return Ok(SelectionResult {
                    relay: score.relay,
                    strategy: SelectionStrategy::Hybrid,
                    score: Some(score.score / total_score),
                    estimated_latency: Some(Duration::from_millis(
                        (1000.0 * (1.0 - score.health_weight)) as u64,
                    )),
                });
            }
            choice -= score.score;
        }

        self.select_random(relays).await
    }
}

/// Calculate approximate distance between two locations in kilometers
fn calculate_distance(
    loc1: &crate::relay_registry::Location,
    loc2: &crate::relay_registry::Location,
) -> f64 {
    // If either location has no coordinates, return max distance
    let (lat1, lon1) = match (loc1.latitude, loc1.longitude) {
        (Some(lat), Some(lon)) => (lat as f64 / 1_000_000.0, lon as f64 / 1_000_000.0),
        _ => return f64::MAX,
    };

    let (lat2, lon2) = match (loc2.latitude, loc2.longitude) {
        (Some(lat), Some(lon)) => (lat as f64 / 1_000_000.0, lon as f64 / 1_000_000.0),
        _ => return f64::MAX,
    };

    // Haversine formula
    let r = 6371.0; // Earth's radius in km
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    r * c
}

/// Selector errors
#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    #[error("No relays available matching criteria")]
    NoRelaysAvailable,
    #[error("Registry error: {0}")]
    RegistryError(String),
    #[error("Selection failed: {0}")]
    SelectionFailed(String),
    #[error("Invalid criteria: {0}")]
    InvalidCriteria(String),
}

/// Selector statistics
#[derive(Debug, Clone)]
pub struct SelectorStatistics {
    /// Number of relays with recent failures
    pub recent_failures: usize,
    /// Total circuits created
    pub total_circuits: u64,
    /// Circuit counts per relay
    pub circuits_per_relay: HashMap<String, u64>,
}

/// Relay pool for managing a set of preferred relays
pub struct RelayPool<R: RelayRegistry + 'static> {
    selector: Arc<RelaySelector<R>>,
    pool_size: usize,
    preferred_relays: Arc<RwLock<Vec<String>>>,
    refresh_interval: Duration,
}

impl<R: RelayRegistry + 'static> RelayPool<R> {
    /// Create a new relay pool
    pub fn new(selector: Arc<RelaySelector<R>>, pool_size: usize) -> Self {
        Self {
            selector,
            pool_size,
            preferred_relays: Arc::new(RwLock::new(Vec::new())),
            refresh_interval: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Initialize the pool (without background task - caller should call refresh periodically)
    pub async fn initialize(&self) -> Result<(), SelectorError> {
        self.refresh().await
    }

    /// Start background refresh task - caller must ensure R: 'static
    pub fn start_background_refresh(self: Arc<Self>)
    where
        R: 'static,
    {
        let preferred = self.preferred_relays.clone();
        let selector = self.selector.clone();
        let interval = self.refresh_interval;
        let pool_size = self.pool_size;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                match selector.select_multiple(pool_size, true).await {
                    Ok(selections) => {
                        let ids: Vec<_> = selections.into_iter().map(|s| s.relay.id).collect();
                        let mut preferred = preferred.write().await;
                        *preferred = ids;
                    }
                    Err(e) => {
                        warn!("Failed to refresh relay pool: {}", e);
                    }
                }
            }
        });
    }

    /// Refresh the pool
    async fn refresh(&self) -> Result<(), SelectorError> {
        let selections = self.selector.select_multiple(self.pool_size, true).await?;
        let ids: Vec<_> = selections.into_iter().map(|s| s.relay.id).collect();

        let mut preferred = self.preferred_relays.write().await;
        *preferred = ids;

        info!("Relay pool refreshed with {} relays", self.pool_size);
        Ok(())
    }

    /// Get a relay from the pool.
    ///
    /// Iterates the pre-selected `preferred_relays` in random order and
    /// returns the first one that is still `is_usable()` in the registry.
    /// Falls back to a fresh `selector.select()` when none of the cached
    /// relays still resolve (network churn, removals) or the pool is empty.
    ///
    /// The previous body iterated `preferred` but did nothing inside the
    /// loop — every call hit the fallback path, making the entire pool
    /// pre-selection logic dead code.
    pub async fn get_relay(&self) -> Result<SelectionResult, SelectorError> {
        let preferred = self.preferred_relays.read().await;

        if preferred.is_empty() {
            drop(preferred);
            return self.selector.select().await;
        }

        let mut rng = rand::thread_rng();
        let mut indices: Vec<_> = (0..preferred.len()).collect();
        indices.shuffle(&mut rng);

        for idx in indices {
            let relay_id = &preferred[idx];
            if let Ok(relay) = self.selector.registry().get_relay(relay_id).await {
                if relay.health_status.is_usable() {
                    return Ok(SelectionResult {
                        relay,
                        strategy: self.selector.strategy(),
                        score: Some(1.0),
                        estimated_latency: None,
                    });
                }
            }
        }

        drop(preferred);
        self.selector.select().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_registry::InMemoryRegistry;

    async fn create_test_registry() -> Arc<InMemoryRegistry> {
        let registry = Arc::new(InMemoryRegistry::new());

        // Add some test relays
        for i in 0..5 {
            let relay = RelayInfo::new(
                format!("192.168.1.{}:9001", i + 1),
                format!("key{}", i),
                (i as u64 + 1) * 1_000_000, // Varying bandwidth
            );
            registry.register(relay).await.unwrap();
        }

        registry
    }

    #[tokio::test]
    async fn test_random_selection() {
        let registry = create_test_registry().await;
        let selector = RelaySelector::new(registry);

        let result = selector.select().await;
        assert!(result.is_ok());

        let selection = result.unwrap();
        assert_eq!(selection.strategy, SelectionStrategy::Hybrid);
    }

    #[tokio::test]
    async fn test_bandwidth_weighted_selection() {
        let registry = create_test_registry().await;
        let config = SelectorConfig {
            strategy: SelectionStrategy::BandwidthWeighted,
            ..Default::default()
        };
        let selector = RelaySelector::with_config(registry, config);

        // Run multiple selections to verify bias toward higher bandwidth
        let mut high_bandwidth_count = 0;
        for _ in 0..100 {
            let result = selector.select().await.unwrap();
            if result.relay.bandwidth >= 4_000_000 {
                high_bandwidth_count += 1;
            }
        }

        // Higher bandwidth relays should be selected more often
        assert!(high_bandwidth_count > 20);
    }

    #[tokio::test]
    async fn test_failed_relay_recovers_after_cooldown() {
        // Regression: a relay that hit max_retries was excluded forever (its
        // retry_count could only be reset by a success, which required being
        // re-selected — impossible while excluded). After the bounded backoff
        // it must become selectable again.
        let registry = Arc::new(InMemoryRegistry::new());
        let relay = RelayInfo::new("192.168.50.1:9001".to_string(), "k".to_string(), 5_000_000);
        let id = relay.id.clone();
        registry.register(relay.clone()).await.unwrap();

        let config = SelectorConfig {
            retry_cooldown: Duration::from_millis(60),
            max_retries: 3,
            ..Default::default()
        };
        let selector = RelaySelector::with_config(registry, config);

        // Drive the relay to max_retries.
        for _ in 0..3 {
            selector
                .report_failure(&id, FailureType::ConnectionFailed)
                .await;
        }
        // During the bounded backoff (cooldown * 3 = 180ms) it is filtered out.
        let filtered = selector.filter_recent_failures(vec![relay.clone()]).await;
        assert!(
            filtered.is_empty(),
            "relay should be filtered while in backoff"
        );

        // After the penalty elapses it must be eligible again (the old code
        // excluded it forever once retry_count >= max_retries).
        tokio::time::sleep(Duration::from_millis(260)).await;
        let filtered = selector.filter_recent_failures(vec![relay]).await;
        assert_eq!(
            filtered.len(),
            1,
            "relay must recover after the cooldown, not be excluded forever"
        );
    }

    #[tokio::test]
    async fn test_failure_tracking() {
        let registry = create_test_registry().await;
        let selector = RelaySelector::new(registry.clone());

        // Select a relay
        let result = selector.select().await.unwrap();
        let relay_id = result.relay.id;

        // Report failures
        for _ in 0..5 {
            selector
                .report_failure(&relay_id, FailureType::ConnectionFailed)
                .await;
        }

        // Check that relay is now avoided
        let stats = selector.get_statistics().await;
        assert_eq!(stats.recent_failures, 1);

        // Clear failures and report success
        selector.clear_failures().await;
        selector.report_success(&relay_id).await;

        let stats = selector.get_statistics().await;
        assert_eq!(stats.recent_failures, 0);
    }

    #[tokio::test]
    async fn test_multiple_selection() {
        let registry = create_test_registry().await;
        let selector = RelaySelector::new(registry);

        let results = selector.select_multiple(3, true).await.unwrap();
        assert_eq!(results.len(), 3);

        // Ensure all relays are unique
        let ids: std::collections::HashSet<_> = results.iter().map(|r| &r.relay.id).collect();
        assert_eq!(ids.len(), 3);
    }
}
