//! Persistent entry guard selection.
//!
//! Guards are long-lived entry relays.  The client picks a small set (typically
//! 2-3) and uses them exclusively as first hops.  This prevents an adversary
//! from mapping a client's circuits by observing which relays are contacted.
//!
//! Guard state is serialised to JSON so that the same guards survive restarts.

use crate::{bootstrap::RelayDescriptor, TransportError};
use chrono::{DateTime, Duration, Utc};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tuning parameters for guard selection and rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// How many guards to maintain simultaneously.
    pub num_guards: usize,
    /// Rotate a guard after it has been selected for this many days.
    pub rotation_days: u64,
    /// Minimum number of usable guards before we fall back to the full relay list.
    pub min_guards: usize,
    /// Maximum consecutive connection failures before a guard is considered unusable.
    pub max_failures: u32,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            num_guards: 3,
            rotation_days: 30,
            min_guards: 1,
            max_failures: 5,
        }
    }
}

// ── GuardEntry ────────────────────────────────────────────────────────────────

/// One entry in the persistent guard set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEntry {
    /// The relay this guard represents.
    pub descriptor: RelayDescriptor,
    /// When this guard was first selected.
    pub selected_at: DateTime<Utc>,
    /// The last time a circuit through this guard succeeded.
    pub last_used: Option<DateTime<Utc>>,
    /// Number of consecutive failures since the last success.
    pub consecutive_failures: u32,
}

impl GuardEntry {
    /// Create a new entry selected right now.
    fn new(descriptor: RelayDescriptor) -> Self {
        Self {
            descriptor,
            selected_at: Utc::now(),
            last_used: None,
            consecutive_failures: 0,
        }
    }

    /// `true` if the guard can be used (not over the failure threshold).
    pub fn is_usable(&self, config: &GuardConfig) -> bool {
        self.consecutive_failures < config.max_failures
    }

    /// Record a successful connection through this guard.
    pub fn mark_success(&mut self) {
        self.last_used = Some(Utc::now());
        self.consecutive_failures = 0;
    }

    /// Record a failed connection attempt through this guard.
    pub fn mark_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// `true` if the guard has been held longer than `rotation_days`.
    fn is_expired(&self, rotation_days: u64) -> bool {
        let age = Utc::now().signed_duration_since(self.selected_at);
        age >= Duration::days(rotation_days as i64)
    }
}

// ── GuardSet ──────────────────────────────────────────────────────────────────

/// The persistent set of selected guards.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardSet {
    pub guards: Vec<GuardEntry>,
}

impl GuardSet {
    // ── Persistence ──────────────────────────────────────────────────────────

    /// Load a previously saved guard set from `path`.
    ///
    /// Returns an empty `GuardSet` (not an error) when the file does not yet
    /// exist so the first-run case is handled transparently.
    pub fn load(path: &Path) -> Result<Self, TransportError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| TransportError::Bootstrap(format!("parse guard state {}: {}", path.display(), e))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("guard state file not found at {}, starting fresh", path.display());
                Ok(GuardSet::default())
            }
            Err(e) => Err(TransportError::Bootstrap(format!(
                "read guard state {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Persist the guard set to `path` (creates parent directories as needed).
    pub fn save(&self, path: &Path) -> Result<(), TransportError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| TransportError::Bootstrap(format!("create guard dir: {}", e)))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| TransportError::Bootstrap(format!("serialize guard state: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| TransportError::Bootstrap(format!("write guard state {}: {}", path.display(), e)))
    }

    // ── Selection ─────────────────────────────────────────────────────────────

    /// Select a new `GuardSet` from `available` relays according to `config`.
    ///
    /// Relays that fail basic validity checks (empty nickname, address, or
    /// pubkey) are excluded from consideration.
    pub fn select_guards(available: &[RelayDescriptor], config: &GuardConfig) -> Self {
        let mut candidates: Vec<RelayDescriptor> = available
            .iter()
            .filter(|r| !r.nickname.is_empty() && !r.address.is_empty() && !r.pubkey_hex.is_empty())
            .cloned()
            .collect();

        candidates.shuffle(&mut rand::thread_rng());
        let take = config.num_guards.min(candidates.len());
        let guards = candidates
            .into_iter()
            .take(take)
            .map(GuardEntry::new)
            .collect();

        GuardSet { guards }
    }

    // ── Access ────────────────────────────────────────────────────────────────

    /// Return how many guards are stored (usable or not).
    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    /// Pick a random usable guard that still appears in `available`.
    ///
    /// Returns `None` if no usable guard exists in the current relay list.
    pub fn get_usable_guard<'a>(
        &'a self,
        available: &'a [RelayDescriptor],
        config: &GuardConfig,
    ) -> Option<&'a RelayDescriptor> {
        // Build a set of known pubkeys for O(1) lookup.
        let known: std::collections::HashSet<&str> =
            available.iter().map(|r| r.pubkey_hex.as_str()).collect();

        let usable: Vec<&RelayDescriptor> = self
            .guards
            .iter()
            .filter(|g| g.is_usable(config) && known.contains(g.descriptor.pubkey_hex.as_str()))
            .map(|g| &g.descriptor)
            .collect();

        usable.choose(&mut rand::thread_rng()).copied()
    }

    /// Replace guards that are either expired or no longer present in `available`.
    pub fn rotate_if_expired(
        &mut self,
        available: &[RelayDescriptor],
        config: &GuardConfig,
    ) {
        let known: std::collections::HashSet<&str> =
            available.iter().map(|r| r.pubkey_hex.as_str()).collect();

        // Remove stale entries.
        self.guards.retain(|g| {
            let expired = g.is_expired(config.rotation_days);
            let gone = !known.contains(g.descriptor.pubkey_hex.as_str());
            if expired {
                info!("rotating expired guard '{}'", g.descriptor.nickname);
            }
            if gone {
                warn!("dropping guard '{}' — no longer in relay list", g.descriptor.nickname);
            }
            !expired && !gone
        });

        // Top-up to the desired count.
        if self.guards.len() < config.num_guards {
            let existing_keys: std::collections::HashSet<&str> =
                self.guards.iter().map(|g| g.descriptor.pubkey_hex.as_str()).collect();

            let mut candidates: Vec<RelayDescriptor> = available
                .iter()
                .filter(|r| {
                    !r.nickname.is_empty()
                        && !r.address.is_empty()
                        && !r.pubkey_hex.is_empty()
                        && !existing_keys.contains(r.pubkey_hex.as_str())
                })
                .cloned()
                .collect();

            candidates.shuffle(&mut rand::thread_rng());
            let needed = config.num_guards - self.guards.len();
            for relay in candidates.into_iter().take(needed) {
                info!("adding new guard '{}'", relay.nickname);
                self.guards.push(GuardEntry::new(relay));
            }
        }
    }

    // ── Mutation helpers ──────────────────────────────────────────────────────

    fn mark_success(&mut self, nickname: &str) {
        if let Some(g) = self.guards.iter_mut().find(|g| g.descriptor.nickname == nickname) {
            g.mark_success();
        }
    }

    fn mark_failure(&mut self, nickname: &str) {
        if let Some(g) = self.guards.iter_mut().find(|g| g.descriptor.nickname == nickname) {
            g.mark_failure();
        }
    }
}

// ── Default path ──────────────────────────────────────────────────────────────

/// Default filesystem path for persisting guard state.
///
/// Returns `None` on platforms where `dirs::data_dir()` is unavailable.
pub fn default_guard_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("gptl").join("guards.json"))
}

// ── GuardManager ─────────────────────────────────────────────────────────────

/// High-level guard management: initialise, persist, and surface an entry relay.
pub struct GuardManager {
    guard_set: GuardSet,
    config: GuardConfig,
    persist_path: Option<PathBuf>,
}

impl GuardManager {
    /// Create a new manager.  Call [`initialize`] before using.
    pub fn new(config: GuardConfig, persist_path: Option<PathBuf>) -> Self {
        Self {
            guard_set: GuardSet::default(),
            config,
            persist_path,
        }
    }

    /// Load persisted state (if any) and ensure at least `min_guards` guards
    /// are selected from `available`.
    pub async fn initialize(&mut self, available: &[RelayDescriptor]) -> Result<(), TransportError> {
        // Load from disk if we have a persist path.
        if let Some(ref path) = self.persist_path {
            self.guard_set = GuardSet::load(path)?;
        }

        // Remove stale/expired entries and top-up.
        self.guard_set.rotate_if_expired(available, &self.config);

        // If still empty, do a fresh selection.
        if self.guard_set.guards.is_empty() {
            self.guard_set = GuardSet::select_guards(available, &self.config);
            info!(
                "selected {} guards from {} available relays",
                self.guard_set.guard_count(),
                available.len()
            );
        }

        Ok(())
    }

    /// Return a reference to a usable entry relay.
    ///
    /// Falls back to the full `available` list when fewer than `min_guards`
    /// usable guards remain.
    pub fn select_entry_relay<'a>(&'a self, available: &'a [RelayDescriptor]) -> Option<&'a RelayDescriptor> {
        let usable_count = self
            .guard_set
            .guards
            .iter()
            .filter(|g| g.is_usable(&self.config))
            .count();

        if usable_count < self.config.min_guards {
            warn!(
                "only {} usable guard(s) — falling back to full relay list",
                usable_count
            );
            return available.choose(&mut rand::thread_rng());
        }

        self.guard_set.get_usable_guard(available, &self.config)
    }

    /// Record a successful connection through the named guard.
    pub fn report_success(&mut self, nickname: &str) {
        self.guard_set.mark_success(nickname);
    }

    /// Record a failed connection attempt through the named guard.
    pub fn report_failure(&mut self, nickname: &str) {
        self.guard_set.mark_failure(nickname);
    }

    /// Persist guard state to disk (no-op if no persist path is set).
    pub async fn save(&self) -> Result<(), TransportError> {
        if let Some(ref path) = self.persist_path {
            self.guard_set.save(path)?;
            debug!("guard state saved to {}", path.display());
        }
        Ok(())
    }

    /// Expose the current guard set (read-only).
    pub fn guard_set(&self) -> &GuardSet {
        &self.guard_set
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `n` fake relay descriptors with distinct keys and addresses.
    fn make_relays(n: usize) -> Vec<RelayDescriptor> {
        (0..n)
            .map(|i| RelayDescriptor {
                nickname: format!("relay-{}", i),
                address: format!("10.0.{}.{}:9001", i / 256, i % 256),
                // 64 hex chars = 32 bytes; each relay gets a distinct key.
                pubkey_hex: format!("{:0>64}", format!("{:x}", i + 1)),
            })
            .collect()
    }

    // ── select_guards ─────────────────────────────────────────────────────────

    #[test]
    fn test_guard_selection_picks_correct_count() {
        let relays = make_relays(10);
        let config = GuardConfig { num_guards: 3, ..Default::default() };
        let gs = GuardSet::select_guards(&relays, &config);
        assert_eq!(gs.guard_count(), 3);
    }

    #[test]
    fn test_guard_selection_with_fewer_relays_than_num_guards() {
        let relays = make_relays(2);
        let config = GuardConfig { num_guards: 5, ..Default::default() };
        let gs = GuardSet::select_guards(&relays, &config);
        assert_eq!(gs.guard_count(), 2);
    }

    #[test]
    fn test_guard_selection_excludes_invalid_relays() {
        let mut relays = make_relays(5);
        // Inject an invalid relay with an empty nickname.
        relays.push(RelayDescriptor {
            nickname: "".into(),
            address: "10.0.5.1:9001".into(),
            pubkey_hex: "a".repeat(64),
        });
        let config = GuardConfig { num_guards: 6, ..Default::default() };
        let gs = GuardSet::select_guards(&relays, &config);
        // At most 5 valid relays can be picked.
        assert!(gs.guard_count() <= 5);
        assert!(gs.guards.iter().all(|g| !g.descriptor.nickname.is_empty()));
    }

    // ── Serialization roundtrip ───────────────────────────────────────────────

    #[test]
    fn test_guard_set_serialization_roundtrip() {
        let relays = make_relays(3);
        let config = GuardConfig::default();
        let original = GuardSet::select_guards(&relays, &config);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guards.json");

        original.save(&path).unwrap();
        let loaded = GuardSet::load(&path).unwrap();

        assert_eq!(original.guard_count(), loaded.guard_count());
        for (a, b) in original.guards.iter().zip(loaded.guards.iter()) {
            assert_eq!(a.descriptor.pubkey_hex, b.descriptor.pubkey_hex);
        }
    }

    #[test]
    fn test_load_nonexistent_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let gs = GuardSet::load(&path).unwrap();
        assert_eq!(gs.guard_count(), 0);
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    #[test]
    fn test_rotation_replaces_expired_guards() {
        let relays = make_relays(10);
        let config = GuardConfig { num_guards: 3, rotation_days: 30, ..Default::default() };
        let mut gs = GuardSet::select_guards(&relays, &config);

        // Artificially age all guards beyond the rotation window.
        let old_time = Utc::now() - Duration::days(31);
        for g in &mut gs.guards {
            g.selected_at = old_time;
        }

        gs.rotate_if_expired(&relays, &config);

        // After rotation: still 3 guards, all with a fresh selection timestamp
        // (within a few seconds of now rather than 31 days ago).
        assert_eq!(gs.guard_count(), 3);
        let threshold = Utc::now() - Duration::seconds(5);
        for g in &gs.guards {
            assert!(
                g.selected_at > threshold,
                "rotated guard '{}' should have a fresh selected_at, got {}",
                g.descriptor.nickname,
                g.selected_at
            );
        }
    }

    #[test]
    fn test_rotation_drops_guards_not_in_available() {
        let relays = make_relays(5);
        let config = GuardConfig { num_guards: 3, ..Default::default() };
        let mut gs = GuardSet::select_guards(&relays, &config);

        // Pass an empty available list — all guards should be dropped.
        gs.rotate_if_expired(&[], &config);
        assert_eq!(gs.guard_count(), 0);
    }

    // ── Failure tracking ──────────────────────────────────────────────────────

    #[test]
    fn test_failure_tracking_marks_guard_unusable() {
        let mut entry = GuardEntry::new(make_relays(1).remove(0));
        let config = GuardConfig { max_failures: 5, ..Default::default() };

        for _ in 0..5 {
            assert!(entry.is_usable(&config), "should still be usable");
            entry.mark_failure();
        }
        assert!(!entry.is_usable(&config), "should be unusable after max_failures");
    }

    #[test]
    fn test_mark_success_resets_failures() {
        let mut entry = GuardEntry::new(make_relays(1).remove(0));
        let config = GuardConfig { max_failures: 3, ..Default::default() };

        entry.mark_failure();
        entry.mark_failure();
        entry.mark_success();

        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.is_usable(&config));
    }

    // ── get_usable_guard ──────────────────────────────────────────────────────

    #[test]
    fn test_get_usable_guard_returns_valid_entry() {
        let relays = make_relays(5);
        let config = GuardConfig { num_guards: 3, ..Default::default() };
        let gs = GuardSet::select_guards(&relays, &config);

        let guard = gs.get_usable_guard(&relays, &config);
        assert!(guard.is_some(), "should find a usable guard");

        // The returned guard must exist in the available list.
        let available_keys: std::collections::HashSet<&str> =
            relays.iter().map(|r| r.pubkey_hex.as_str()).collect();
        assert!(available_keys.contains(guard.unwrap().pubkey_hex.as_str()));
    }

    #[test]
    fn test_get_usable_guard_none_when_not_in_available() {
        let relays = make_relays(3);
        let config = GuardConfig { num_guards: 3, ..Default::default() };
        let gs = GuardSet::select_guards(&relays, &config);

        // Pass an empty available list.
        let guard = gs.get_usable_guard(&[], &config);
        assert!(guard.is_none());
    }

    // ── GuardManager ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_manager_initialize_and_persist() {
        let relays = make_relays(5);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guards.json");

        let config = GuardConfig { num_guards: 2, ..Default::default() };
        let mut manager = GuardManager::new(config.clone(), Some(path.clone()));
        manager.initialize(&relays).await.unwrap();
        assert_eq!(manager.guard_set().guard_count(), 2);

        manager.save().await.unwrap();

        // A second manager should load the same guards.
        let mut manager2 = GuardManager::new(config, Some(path));
        manager2.initialize(&relays).await.unwrap();
        assert_eq!(manager2.guard_set().guard_count(), 2);
    }

    #[tokio::test]
    async fn test_manager_report_failure_propagates() {
        let relays = make_relays(5);
        let config = GuardConfig { num_guards: 1, max_failures: 2, ..Default::default() };
        let mut manager = GuardManager::new(config, None);
        manager.initialize(&relays).await.unwrap();

        let nickname = manager.guard_set().guards[0].descriptor.nickname.clone();
        manager.report_failure(&nickname);
        manager.report_failure(&nickname);

        let entry = manager
            .guard_set()
            .guards
            .iter()
            .find(|g| g.descriptor.nickname == nickname)
            .unwrap();
        assert_eq!(entry.consecutive_failures, 2);
    }
}
