//! Adapter that lets a `gptl-transport` proxy report circuit events
//! into `gptl-routing`'s `CircuitHealthMonitor` and `FailoverManager`.
//!
//! The transport layer defines a non-async `CircuitObserver` trait;
//! this module implements it by spawning short tokio tasks that drive
//! the async health monitor.  Keeping the implementation here (rather
//! than in transport) keeps the transport free of any routing-layer
//! dependency.

use crate::circuit::health::{CircuitHealthMonitor, FailureType as HealthFailure};
use crate::failover::{FailoverManager, FailureType as FailoverFailure};
use gptl_core::relay_registry::{RelayInfo, RelayRegistry};
use gptl_transport::observer::{CircuitObserver, FailureKind};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Wraps a [`CircuitHealthMonitor`] so it can be plugged into the
/// transport's `ProxyConfig::observer` field.
///
/// Each event becomes a short tokio task so the proxy's hot path is
/// never blocked on the monitor's `RwLock`s.
///
/// `FailoverManager` is intentionally NOT wired here because it's
/// generic over a registry type (`FailoverManager<R: RelayRegistry>`)
/// — type-erasing that into a single bridge would require either a
/// concrete registry choice or a second trait.  Users with failover
/// needs can compose a custom observer that delegates to this bridge
/// AND their own failover wiring.
#[derive(Clone)]
pub struct TransportBridge {
    health: Arc<CircuitHealthMonitor>,
}

impl TransportBridge {
    /// Build a bridge that reports circuit events to the health monitor.
    pub fn new(health: Arc<CircuitHealthMonitor>) -> Self {
        Self { health }
    }
}

impl std::fmt::Debug for TransportBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportBridge").finish()
    }
}

fn classify(kind: FailureKind) -> HealthFailure {
    match kind {
        FailureKind::Handshake => HealthFailure::ConnectionFailed,
        FailureKind::Extend => HealthFailure::ProtocolError,
        FailureKind::Stream => HealthFailure::ConnectionFailed,
        FailureKind::CircuitDrop => HealthFailure::ConnectionFailed,
        FailureKind::Other => HealthFailure::ProtocolError,
    }
}

impl CircuitObserver for TransportBridge {
    fn register(&self, circuit_id: u32, _relay_label: &str) {
        let monitor = Arc::clone(&self.health);
        tokio::spawn(async move {
            monitor.register_circuit(circuit_id as u64).await;
        });
    }

    fn record_success(&self, circuit_id: u32, latency: Duration, bytes: u64) {
        let monitor = Arc::clone(&self.health);
        tokio::spawn(async move {
            monitor
                .record_success(circuit_id as u64, latency, bytes)
                .await;
        });
    }

    fn record_failure(&self, circuit_id: u32, kind: FailureKind, _reason: &str) {
        let monitor = Arc::clone(&self.health);
        let health_kind = classify(kind);
        tokio::spawn(async move {
            monitor.record_failure(circuit_id as u64, health_kind).await;
        });
    }

    fn unregister(&self, circuit_id: u32) {
        let monitor = Arc::clone(&self.health);
        tokio::spawn(async move {
            monitor.unregister_circuit(circuit_id as u64).await;
        });
    }
}

// ── FailoverBridge ───────────────────────────────────────────────────────────

/// Bridge that drives a [`FailoverManager`] from the transport
/// observer events.
///
/// `FailoverManager` is generic over a `RelayRegistry` impl, so the
/// bridge is too.  It accepts an optional secondary
/// [`CircuitHealthMonitor`] so callers can wire BOTH the health
/// monitor and the failover manager from a single observer — or, for
/// finer control, compose two separate bridges through
/// [`gptl_transport::observer::CompositeObserver`].
///
/// `FailoverManager::register_circuit` wants a full `RelayInfo`, but
/// the transport observer only knows the entry-relay nickname.  The
/// bridge holds a label→`RelayInfo` map populated via
/// [`set_known_relays`]; if the label isn't in the map (e.g. the
/// "random-relay" legacy path), the failover register call is
/// silently skipped — the health monitor still receives the event.
pub struct FailoverBridge<R: RelayRegistry + 'static> {
    failover: Arc<FailoverManager<R>>,
    health: Option<Arc<CircuitHealthMonitor>>,
    nickname_map: Arc<RwLock<HashMap<String, RelayInfo>>>,
}

impl<R: RelayRegistry + 'static> FailoverBridge<R> {
    /// Build a bridge that forwards observer events to `failover`.
    pub fn new(failover: Arc<FailoverManager<R>>) -> Self {
        Self {
            failover,
            health: None,
            nickname_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Also forward register/success/failure/unregister to the given
    /// health monitor.  Equivalent to wrapping this bridge in a
    /// `CompositeObserver` together with a `TransportBridge` but
    /// avoids the extra layer.
    pub fn with_health_monitor(mut self, health: Arc<CircuitHealthMonitor>) -> Self {
        self.health = Some(health);
        self
    }

    /// Populate the nickname→`RelayInfo` lookup table.  Call this once
    /// at startup (and again whenever the relay set changes) so the
    /// bridge can convert observer labels into the `RelayInfo` values
    /// `FailoverManager::register_circuit` requires.
    pub async fn set_known_relays(&self, entries: &[(String, RelayInfo)]) {
        let mut map = self.nickname_map.write().await;
        map.clear();
        for (k, v) in entries {
            map.insert(k.clone(), v.clone());
        }
    }

    fn lookup_relay(&self, nickname: &str) -> Option<RelayInfo> {
        // Try a blocking lock — the map is rarely contended.
        self.nickname_map
            .try_read()
            .ok()
            .and_then(|m| m.get(nickname).cloned())
    }
}

impl<R: RelayRegistry + 'static> std::fmt::Debug for FailoverBridge<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailoverBridge")
            .field("has_health_monitor", &self.health.is_some())
            .finish()
    }
}

impl<R: RelayRegistry + 'static> CircuitObserver for FailoverBridge<R> {
    fn register(&self, circuit_id: u32, relay_label: &str) {
        if let Some(ref monitor) = self.health {
            let m = Arc::clone(monitor);
            tokio::spawn(async move {
                m.register_circuit(circuit_id as u64).await;
            });
        }
        if let Some(relay) = self.lookup_relay(relay_label) {
            let failover = Arc::clone(&self.failover);
            tokio::spawn(async move {
                let _ = failover.register_circuit(circuit_id, relay).await;
            });
        }
    }

    fn record_success(&self, circuit_id: u32, latency: Duration, bytes: u64) {
        if let Some(ref monitor) = self.health {
            let m = Arc::clone(monitor);
            tokio::spawn(async move {
                m.record_success(circuit_id as u64, latency, bytes).await;
            });
        }
        if bytes > 0 {
            let failover = Arc::clone(&self.failover);
            tokio::spawn(async move {
                let _ = failover.report_activity(circuit_id, bytes).await;
            });
        }
    }

    fn record_failure(&self, circuit_id: u32, kind: FailureKind, _reason: &str) {
        let health_kind = classify(kind);
        let failover_kind = classify_failover(kind);
        if let Some(ref monitor) = self.health {
            let m = Arc::clone(monitor);
            tokio::spawn(async move {
                m.record_failure(circuit_id as u64, health_kind).await;
            });
        }
        let failover = Arc::clone(&self.failover);
        tokio::spawn(async move {
            // `report_failure` returns Err when the circuit isn't known
            // (e.g. the register path skipped because the nickname
            // wasn't in the map).  Ignoring it is correct: health
            // monitoring still runs.
            let _ = failover.report_failure(circuit_id, failover_kind).await;
        });
    }

    fn unregister(&self, circuit_id: u32) {
        if let Some(ref monitor) = self.health {
            let m = Arc::clone(monitor);
            tokio::spawn(async move {
                m.unregister_circuit(circuit_id as u64).await;
            });
        }
        // FailoverManager has no explicit unregister; circuits live in
        // its active_circuits map until a failure removes them.  That's
        // the intended semantics — there's nothing to call here.
    }
}

fn classify_failover(kind: FailureKind) -> FailoverFailure {
    match kind {
        FailureKind::Handshake => FailoverFailure::ConnectionFailed,
        FailureKind::Extend => FailoverFailure::ProtocolError,
        FailureKind::Stream => FailoverFailure::Rejected,
        FailureKind::CircuitDrop => FailoverFailure::ConnectionFailed,
        FailureKind::Other => FailoverFailure::ProtocolError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Tiny smoke test: build a bridge, fire each event type, give the
    /// tokio runtime a moment to process the spawned tasks, then verify
    /// the underlying health monitor reflects the activity.
    #[tokio::test]
    async fn test_bridge_forwards_register_success_unregister() {
        let monitor = Arc::new(CircuitHealthMonitor::new());
        let bridge = TransportBridge::new(Arc::clone(&monitor));

        bridge.register(42, "alpha");
        bridge.record_success(42, Duration::from_millis(120), 1024);

        // Spawned tasks need a moment to complete.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let status = monitor.get_health_status(42).await;
        assert!(status.is_some(), "monitor must have registered circuit 42");

        bridge.unregister(42);
        tokio::time::sleep(Duration::from_millis(50)).await;
        let status_after = monitor.get_health_status(42).await;
        assert!(
            status_after.is_none(),
            "monitor must have removed circuit 42 after unregister"
        );
    }

    #[tokio::test]
    async fn test_bridge_classifies_failure_kinds() {
        // Each FailureKind should map to a non-panicking health failure.
        for kind in [
            FailureKind::Handshake,
            FailureKind::Extend,
            FailureKind::Stream,
            FailureKind::CircuitDrop,
            FailureKind::Other,
        ] {
            let _h = classify(kind);
        }
    }

    #[tokio::test]
    async fn test_failover_bridge_register_via_nickname_lookup() {
        use crate::circuit::health::CircuitHealthMonitor;
        use crate::failover::FailoverManager;
        use gptl_core::relay_registry::{InMemoryRegistry, RelayInfo};
        use gptl_core::relay_selector::RelaySelector;

        let registry = Arc::new(InMemoryRegistry::new());
        let info = RelayInfo::new("10.0.0.1:9001", "abc", 1_000_000).with_nickname("alpha");
        registry.register(info.clone()).await.unwrap();

        let selector = Arc::new(RelaySelector::new(Arc::clone(&registry)));
        let monitor = Arc::new(CircuitHealthMonitor::new());
        let failover = Arc::new(FailoverManager::new(Arc::clone(&registry), selector));

        let bridge =
            FailoverBridge::new(Arc::clone(&failover)).with_health_monitor(Arc::clone(&monitor));
        bridge
            .set_known_relays(&[("alpha".to_string(), info)])
            .await;

        bridge.register(123, "alpha");
        bridge.record_failure(123, FailureKind::Stream, "EOF");

        tokio::time::sleep(Duration::from_millis(80)).await;

        let status = monitor.get_health_status(123).await;
        assert!(
            status.is_some(),
            "after FailoverBridge::register the monitor must know about circuit 123"
        );
    }

    #[tokio::test]
    async fn test_failover_bridge_unknown_nickname_skips_silently() {
        use crate::failover::FailoverManager;
        use gptl_core::relay_registry::InMemoryRegistry;
        use gptl_core::relay_selector::RelaySelector;

        let registry = Arc::new(InMemoryRegistry::new());
        let selector = Arc::new(RelaySelector::new(Arc::clone(&registry)));
        let failover = Arc::new(FailoverManager::new(registry, selector));
        let bridge = FailoverBridge::new(failover);

        // Calling register with an unknown nickname must not panic.
        bridge.register(1, "ghost-relay");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn test_bridge_record_failure_drives_health_monitor() {
        let monitor = Arc::new(CircuitHealthMonitor::new());
        let bridge = TransportBridge::new(Arc::clone(&monitor));

        bridge.register(7, "alpha");
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Hammer the circuit with failures.
        for _ in 0..10 {
            bridge.record_failure(7, FailureKind::Stream, "EOF");
        }
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Status must have degraded.
        let status = monitor.get_health_status(7).await.unwrap();
        assert!(
            !matches!(status, crate::circuit::health::HealthStatus::Healthy),
            "after 10 failures the circuit must no longer be Healthy; got {:?}",
            status
        );
    }
}
