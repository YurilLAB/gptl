//! Circuit lifecycle observer trait.
//!
//! `gptl-transport`'s proxy emits circuit-lifecycle events (register,
//! success, failure, unregister) through this trait so external
//! monitoring layers — most notably `gptl-routing`'s
//! `CircuitHealthMonitor` and `FailoverManager` — can drive their
//! health-ranking and rotation logic.
//!
//! The trait is non-async on purpose: implementations that need to
//! mutate async state can spawn a short task internally.  This keeps
//! the hot path on the proxy side from being slowed down by
//! observer-side locks.

use std::sync::Arc;
use std::time::Duration;

/// Why a circuit reported a failure.  Kept small and observer-agnostic;
/// callers (e.g. `gptl-routing`) translate to their own richer enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Could not connect to the entry relay or complete the handshake.
    Handshake,
    /// Could not extend the circuit to a subsequent hop.
    Extend,
    /// RELAY_BEGIN was refused, target unreachable, or stream-level
    /// I/O error during data transit.
    Stream,
    /// Circuit died unexpectedly (peer dropped TCP, etc.).
    CircuitDrop,
    /// Catch-all for anything else.
    Other,
}

/// Hook called by the proxy at circuit lifecycle boundaries.
///
/// Implementations MUST be cheap and non-blocking — they're called
/// from the proxy's hot path.  Use internal task-spawn / atomics if
/// you need to do any async work.
pub trait CircuitObserver: Send + Sync + std::fmt::Debug {
    /// A new circuit has just completed its handshake and is about to
    /// start carrying streams.  `relay_label` is a human-readable
    /// identifier for the entry hop (typically the relay nickname).
    fn register(&self, circuit_id: u32, relay_label: &str);

    /// The circuit completed a unit of work (one stream's full
    /// request/response, including byte count and elapsed time).
    fn record_success(&self, circuit_id: u32, latency: Duration, bytes: u64);

    /// The circuit experienced a failure at the given stage.
    fn record_failure(&self, circuit_id: u32, kind: FailureKind, reason: &str);

    /// The circuit is being torn down.  After this call the observer
    /// should release any per-circuit state.
    fn unregister(&self, circuit_id: u32);
}

/// Convenience: an observer that ignores every event.  Used as the
/// default when no monitoring is configured.
#[derive(Debug, Clone, Default)]
pub struct NoopObserver;

impl CircuitObserver for NoopObserver {
    fn register(&self, _: u32, _: &str) {}
    fn record_success(&self, _: u32, _: Duration, _: u64) {}
    fn record_failure(&self, _: u32, _: FailureKind, _: &str) {}
    fn unregister(&self, _: u32) {}
}

/// Convenience alias.  Most callers store the observer behind an `Arc`
/// so it can be cloned cheaply into background tasks.
pub type SharedObserver = Arc<dyn CircuitObserver>;

/// Returns a no-op observer wrapped in an `Arc` — usable wherever a
/// `SharedObserver` is required but no real monitoring is wanted.
pub fn noop_observer() -> SharedObserver {
    Arc::new(NoopObserver)
}

/// Fan-out observer that forwards every event to a fixed list of
/// child observers in order.
///
/// Use this when you want to attach multiple unrelated monitors to a
/// single proxy (e.g. the routing-layer health monitor, a Prometheus
/// metrics counter, and an audit-log sink).  Errors and panics in one
/// observer DO NOT propagate to the others — each event is forwarded
/// inside a `catch_unwind` so a buggy child can't take the proxy down.
///
/// ```no_run
/// # use std::sync::Arc;
/// # use gptl_transport::observer::{CompositeObserver, CircuitObserver, NoopObserver, SharedObserver};
/// let multi: SharedObserver = Arc::new(
///     CompositeObserver::from(vec![
///         Arc::new(NoopObserver) as SharedObserver,
///         // ... real observers here ...
///     ])
/// );
/// ```
#[derive(Clone, Default)]
pub struct CompositeObserver {
    children: Vec<SharedObserver>,
}

impl std::fmt::Debug for CompositeObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeObserver")
            .field("children", &self.children.len())
            .finish()
    }
}

impl CompositeObserver {
    /// Build an empty composite.  Add children with [`push`].
    pub fn new() -> Self {
        Self { children: Vec::new() }
    }

    /// Append a child observer.  Returns `self` for chaining.
    pub fn push(mut self, child: SharedObserver) -> Self {
        self.children.push(child);
        self
    }

    /// Number of child observers attached.
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// True when no children are attached (equivalent to a no-op observer).
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

impl From<Vec<SharedObserver>> for CompositeObserver {
    fn from(children: Vec<SharedObserver>) -> Self {
        Self { children }
    }
}

impl CircuitObserver for CompositeObserver {
    fn register(&self, circuit_id: u32, relay_label: &str) {
        for child in &self.children {
            // `catch_unwind` over a non-`Send` `&dyn` closure: we wrap
            // each forwarding call so a panicking observer can't
            // poison the others.  Note this only catches *panics*;
            // observers that emit no panic but do something
            // unfortunate (silent task spawn that's slow) still affect
            // throughput.
            let c = child.clone();
            let label = relay_label.to_string();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                c.register(circuit_id, &label)
            }));
        }
    }

    fn record_success(&self, circuit_id: u32, latency: Duration, bytes: u64) {
        for child in &self.children {
            let c = child.clone();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                c.record_success(circuit_id, latency, bytes)
            }));
        }
    }

    fn record_failure(&self, circuit_id: u32, kind: FailureKind, reason: &str) {
        for child in &self.children {
            let c = child.clone();
            let r = reason.to_string();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                c.record_failure(circuit_id, kind, &r)
            }));
        }
    }

    fn unregister(&self, circuit_id: u32) {
        for child in &self.children {
            let c = child.clone();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                c.unregister(circuit_id)
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct CountingObserver {
        registered: Mutex<Vec<u32>>,
        successes: Mutex<Vec<(u32, Duration, u64)>>,
        failures: Mutex<Vec<(u32, FailureKind, String)>>,
        unregistered: Mutex<Vec<u32>>,
    }

    impl CircuitObserver for CountingObserver {
        fn register(&self, id: u32, _label: &str) {
            self.registered.lock().unwrap().push(id);
        }
        fn record_success(&self, id: u32, lat: Duration, b: u64) {
            self.successes.lock().unwrap().push((id, lat, b));
        }
        fn record_failure(&self, id: u32, kind: FailureKind, reason: &str) {
            self.failures
                .lock()
                .unwrap()
                .push((id, kind, reason.to_string()));
        }
        fn unregister(&self, id: u32) {
            self.unregistered.lock().unwrap().push(id);
        }
    }

    #[test]
    fn test_noop_observer_doesnt_panic() {
        let n = NoopObserver;
        n.register(1, "x");
        n.record_success(1, Duration::from_millis(10), 100);
        n.record_failure(1, FailureKind::Stream, "x");
        n.unregister(1);
    }

    #[test]
    fn test_counting_observer_records_each_event_type() {
        let obs = CountingObserver::default();
        obs.register(42, "alpha");
        obs.record_success(42, Duration::from_millis(50), 1024);
        obs.record_failure(42, FailureKind::Stream, "EOF");
        obs.unregister(42);

        assert_eq!(obs.registered.lock().unwrap().as_slice(), &[42]);
        assert_eq!(obs.successes.lock().unwrap().len(), 1);
        assert_eq!(obs.failures.lock().unwrap().len(), 1);
        assert_eq!(obs.unregistered.lock().unwrap().as_slice(), &[42]);
    }

    #[test]
    fn test_shared_observer_can_be_cloned() {
        let obs: SharedObserver = Arc::new(CountingObserver::default());
        let clone = Arc::clone(&obs);
        obs.register(1, "a");
        clone.register(2, "b");
        // We can't downcast in the trait-object world; assert via Arc count.
        assert!(Arc::strong_count(&obs) >= 2);
    }

    #[test]
    fn test_composite_observer_fans_out_to_every_child() {
        let a = Arc::new(CountingObserver::default());
        let b = Arc::new(CountingObserver::default());
        let composite = CompositeObserver::new()
            .push(a.clone() as SharedObserver)
            .push(b.clone() as SharedObserver);

        composite.register(7, "alpha");
        composite.record_success(7, Duration::from_millis(11), 99);
        composite.record_failure(7, FailureKind::Stream, "boom");
        composite.unregister(7);

        for obs in [&a, &b] {
            assert_eq!(obs.registered.lock().unwrap().as_slice(), &[7]);
            assert_eq!(obs.successes.lock().unwrap().len(), 1);
            assert_eq!(obs.failures.lock().unwrap().len(), 1);
            assert_eq!(obs.unregistered.lock().unwrap().as_slice(), &[7]);
        }
    }

    /// A child observer that panics on every call must NOT prevent the
    /// other children from getting the event.
    #[test]
    fn test_composite_isolates_panicking_child() {
        #[derive(Debug)]
        struct Panicker;
        impl CircuitObserver for Panicker {
            fn register(&self, _: u32, _: &str) {
                panic!("intentional");
            }
            fn record_success(&self, _: u32, _: Duration, _: u64) {
                panic!("intentional");
            }
            fn record_failure(&self, _: u32, _: FailureKind, _: &str) {
                panic!("intentional");
            }
            fn unregister(&self, _: u32) {
                panic!("intentional");
            }
        }

        let good = Arc::new(CountingObserver::default());
        let composite = CompositeObserver::new()
            .push(Arc::new(Panicker) as SharedObserver)
            .push(good.clone() as SharedObserver);

        composite.register(1, "a");
        composite.record_success(1, Duration::from_millis(5), 42);
        composite.record_failure(1, FailureKind::Handshake, "x");
        composite.unregister(1);

        assert_eq!(good.registered.lock().unwrap().as_slice(), &[1]);
        assert_eq!(good.successes.lock().unwrap().len(), 1);
        assert_eq!(good.failures.lock().unwrap().len(), 1);
        assert_eq!(good.unregistered.lock().unwrap().as_slice(), &[1]);
    }

    #[test]
    fn test_composite_empty_is_silent_noop() {
        let c = CompositeObserver::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
        // No-op behavior: every call must succeed without panic.
        c.register(1, "x");
        c.record_success(1, Duration::from_millis(1), 1);
        c.record_failure(1, FailureKind::Other, "y");
        c.unregister(1);
    }
}
