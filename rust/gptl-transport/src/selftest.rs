//! Startup self-test for the GPTL client.
//!
//! Before declaring the SOCKS5 proxy ready, probe each configured relay
//! and verify that:
//!
//!   1. TCP connect to the relay's advertised address succeeds within a
//!      bounded timeout.
//!   2. A complete ntor-lite handshake (CREATE → CREATED → key confirm)
//!      succeeds, producing valid session keys.
//!
//! Each probe is run in parallel.  The function returns per-relay
//! results so the caller can decide how to report (log, refuse to
//! start, warn-and-continue).
//!
//! The probes do NOT do a full HTTP request through the relay — that
//! would require an exit destination and would add latency on every
//! startup.  Handshake success is a strong signal that the relay is
//! online, has the advertised key, and is willing to build circuits.

use crate::{
    bootstrap::RelayDescriptor,
    cell::{Cell, CellType, CELL_SIZE},
    handshake::{client_finish, client_initiate},
    relay_conn::RelayConn,
    TransportError,
};
use std::time::{Duration, Instant};

/// Per-relay self-test outcome.
#[derive(Debug, Clone)]
pub struct RelayProbeResult {
    /// Display name of the relay (`RelayDescriptor::nickname`).
    pub nickname: String,
    /// Advertised `host:port` from the descriptor.
    pub address: String,
    /// Result of the handshake probe.
    pub outcome: ProbeOutcome,
    /// Round-trip time observed for the handshake.
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub enum ProbeOutcome {
    /// TCP connect + handshake succeeded.
    Healthy,
    /// TCP connect succeeded, handshake failed.  Carries the error string.
    HandshakeFailed(String),
    /// TCP connect / address parse failed.  Carries the error string.
    Unreachable(String),
    /// Probe did not complete within `timeout`.
    TimedOut,
}

impl ProbeOutcome {
    pub fn is_healthy(&self) -> bool {
        matches!(self, ProbeOutcome::Healthy)
    }
    pub fn describe(&self) -> String {
        match self {
            ProbeOutcome::Healthy => "ok".to_string(),
            ProbeOutcome::HandshakeFailed(s) => format!("handshake failed: {}", s),
            ProbeOutcome::Unreachable(s) => format!("unreachable: {}", s),
            ProbeOutcome::TimedOut => "timed out".to_string(),
        }
    }
}

/// Probe every relay in `relays` in parallel.
///
/// Returns a `RelayProbeResult` per relay, in the same order.
/// `timeout` bounds each individual probe (default 5s is reasonable for
/// loopback / LAN; remote relays may need 10–15s).
pub async fn probe_all(relays: &[RelayDescriptor], timeout: Duration) -> Vec<RelayProbeResult> {
    let handles: Vec<_> = relays
        .iter()
        .cloned()
        .map(|r| tokio::spawn(probe_one(r, timeout)))
        .collect();

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(r) => out.push(r),
            Err(_join) => {
                // Should not happen for a well-formed runtime; surface as
                // an Unreachable for the matching relay so the caller still
                // gets a complete result vector.
                out.push(RelayProbeResult {
                    nickname: "?".to_string(),
                    address: "?".to_string(),
                    outcome: ProbeOutcome::Unreachable("probe task panicked".to_string()),
                    elapsed: Duration::ZERO,
                });
            }
        }
    }
    out
}

/// Probe a single relay: TCP connect → CREATE → CREATED → confirm.
async fn probe_one(relay: RelayDescriptor, timeout: Duration) -> RelayProbeResult {
    let started = Instant::now();
    let outcome = match tokio::time::timeout(timeout, probe_inner(&relay)).await {
        Ok(Ok(())) => ProbeOutcome::Healthy,
        Ok(Err(TransportError::Bootstrap(e))) => ProbeOutcome::Unreachable(e),
        Ok(Err(TransportError::Io(e))) => ProbeOutcome::Unreachable(e),
        Ok(Err(TransportError::Handshake(e))) => ProbeOutcome::HandshakeFailed(e),
        Ok(Err(e)) => ProbeOutcome::HandshakeFailed(e.to_string()),
        Err(_elapsed) => ProbeOutcome::TimedOut,
    };
    RelayProbeResult {
        nickname: relay.nickname,
        address: relay.address,
        outcome,
        elapsed: started.elapsed(),
    }
}

async fn probe_inner(relay: &RelayDescriptor) -> Result<(), TransportError> {
    // Parse the address (we re-do this even though BootstrapConfig::validate
    // also parses it, because validate runs on the whole directory and
    // self-test should report a per-relay failure rather than aborting).
    let addr: std::net::SocketAddr = relay.address.parse().map_err(|e| {
        TransportError::Bootstrap(format!("bad address '{}': {}", relay.address, e))
    })?;

    // Decode the relay's static pubkey.
    let static_pub = relay.pubkey_bytes()?;

    // Connect and run the handshake.
    let mut conn = RelayConn::connect(addr).await?;

    // Pick an arbitrary non-zero, odd circuit ID (matches client convention).
    let circuit_id = 0x6470_746cu32 | 1; // "gptl" with low bit set; just needs to be non-zero/odd
    let (create_cell, pending) = client_initiate(circuit_id, &static_pub)?;

    conn.send(&create_cell).await?;

    // Read response — expect a CREATED cell.  We re-use RelayConn::recv,
    // which already enforces the 512-byte frame.
    let created = conn.recv().await?;
    if !matches!(created.cell_type, CellType::Created) {
        return Err(TransportError::Handshake(format!(
            "expected CREATED, got {:?}",
            created.cell_type
        )));
    }
    let _session_keys = client_finish(pending, &created)?;

    // Send DESTROY so the relay frees the circuit immediately instead of
    // waiting for the read-timeout.  Best-effort; ignore errors.
    let destroy = Cell::new(circuit_id, CellType::Destroy);
    let _ = conn.send(&destroy).await;
    conn.shutdown().await;
    // Silence unused-const warning if CELL_SIZE moves; keep the import for
    // future probe variants that read raw bytes.
    let _ = CELL_SIZE;
    Ok(())
}

/// Render `results` as a human-readable summary suitable for `info!`.
pub fn format_summary(results: &[RelayProbeResult]) -> String {
    use std::fmt::Write;
    let healthy = results.iter().filter(|r| r.outcome.is_healthy()).count();
    let total = results.len();
    let mut s = format!("self-test: {}/{} relays healthy", healthy, total);
    for r in results {
        let _ = write!(
            s,
            "\n  [{:>4}ms] {:<24} {:<22} {}",
            r.elapsed.as_millis(),
            r.address,
            format_truncate(&r.nickname, 22),
            r.outcome.describe(),
        );
    }
    s
}

fn format_truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{relay_respond, RelayStaticKey};
    use crate::relay_conn::RelayConn;
    use tokio::net::TcpListener;

    /// Spawn a fake relay that responds correctly to one CREATE cell.
    async fn spawn_real_relay(key: RelayStaticKey) -> RelayDescriptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pubkey_hex = hex::encode(key.public);

        tokio::spawn(async move {
            // Accept ONE connection, respond to CREATE, then close.
            if let Ok((stream, _peer)) = listener.accept().await {
                let mut conn = RelayConn::new(stream);
                if let Ok(create) = conn.recv().await {
                    if let Ok((created, _session)) = relay_respond(&create, &key) {
                        let _ = conn.send(&created).await;
                        // Read whatever DESTROY the probe sends, ignore.
                        let _ = conn.recv().await;
                    }
                }
            }
        });

        RelayDescriptor {
            nickname: "good-relay".to_string(),
            address: addr.to_string(),
            pubkey_hex,
        }
    }

    /// Spawn a fake relay that accepts TCP but never responds.
    async fn spawn_silent_relay() -> RelayDescriptor {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept and hold forever.
            if let Ok((stream, _)) = listener.accept().await {
                let _ = stream.set_nodelay(true);
                std::future::pending::<()>().await;
            }
        });
        RelayDescriptor {
            nickname: "silent-relay".to_string(),
            address: addr.to_string(),
            // Random pubkey; we expect this to time out before pubkey matters.
            pubkey_hex: "00".repeat(32),
        }
    }

    #[tokio::test]
    async fn test_probe_healthy_relay_succeeds() {
        let key = RelayStaticKey::generate();
        let desc = spawn_real_relay(key).await;
        let results = probe_all(&[desc], Duration::from_secs(3)).await;
        assert_eq!(results.len(), 1);
        assert!(
            results[0].outcome.is_healthy(),
            "probe must succeed against a real relay; got {:?}",
            results[0].outcome
        );
        assert!(results[0].elapsed < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_probe_silent_relay_times_out() {
        let desc = spawn_silent_relay().await;
        let results = probe_all(&[desc], Duration::from_millis(400)).await;
        assert_eq!(results.len(), 1);
        assert!(
            matches!(results[0].outcome, ProbeOutcome::TimedOut),
            "silent relay must time out; got {:?}",
            results[0].outcome
        );
    }

    #[tokio::test]
    async fn test_probe_unreachable_relay_reports_failure() {
        // Bind a port then immediately drop the listener.  On Linux this
        // produces ECONNREFUSED (→ Unreachable); on Windows the connect
        // call may instead hang briefly before being killed by the probe
        // timeout (→ TimedOut).  We accept either — the goal is "not
        // Healthy and not HandshakeFailed."
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let desc = RelayDescriptor {
            nickname: "dead-relay".to_string(),
            address: addr.to_string(),
            pubkey_hex: "11".repeat(32),
        };
        let results = probe_all(&[desc], Duration::from_millis(800)).await;
        assert_eq!(results.len(), 1);
        assert!(
            matches!(
                results[0].outcome,
                ProbeOutcome::Unreachable(_) | ProbeOutcome::TimedOut
            ),
            "expected Unreachable or TimedOut, got {:?}",
            results[0].outcome
        );
    }

    #[tokio::test]
    async fn test_probe_all_runs_in_parallel() {
        // Three healthy relays — total time should be close to one round-trip,
        // not 3x.  Use an explicit small upper bound to assert parallelism.
        let mut descs = Vec::with_capacity(3);
        for _ in 0..3 {
            descs.push(spawn_real_relay(RelayStaticKey::generate()).await);
        }

        let started = std::time::Instant::now();
        let results = probe_all(&descs, Duration::from_secs(3)).await;
        let elapsed = started.elapsed();

        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.outcome.is_healthy(), "{:?}", r);
        }
        // Even on a slow machine, three local handshakes in parallel
        // should comfortably complete in <800ms.
        assert!(
            elapsed < Duration::from_millis(800),
            "probes did not run in parallel: total elapsed = {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_summary_includes_per_relay_lines() {
        let results = vec![
            RelayProbeResult {
                nickname: "alpha".to_string(),
                address: "127.0.0.1:9001".to_string(),
                outcome: ProbeOutcome::Healthy,
                elapsed: Duration::from_millis(12),
            },
            RelayProbeResult {
                nickname: "beta".to_string(),
                address: "127.0.0.1:9002".to_string(),
                outcome: ProbeOutcome::TimedOut,
                elapsed: Duration::from_millis(500),
            },
        ];
        let s = format_summary(&results);
        assert!(s.contains("1/2 relays healthy"));
        assert!(s.contains("alpha"));
        assert!(s.contains("beta"));
        assert!(s.contains("ok"));
        assert!(s.contains("timed out"));
    }
}
