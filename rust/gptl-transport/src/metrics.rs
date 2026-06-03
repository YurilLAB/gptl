//! Prometheus-style metrics for the relay node and SOCKS5 client.
//!
//! All counters are `AtomicU64` so they can be incremented from the
//! proxy / relay hot paths without locking.  The render functions
//! produce text in the OpenMetrics / Prometheus exposition format
//! (https://prometheus.io/docs/instrumenting/exposition_formats/).
//!
//! Wire counters by:
//!   1. Holding an `Arc<RelayMetrics>` (or `Arc<ClientMetrics>`)
//!      in the surrounding struct.
//!   2. Calling `metrics.foo.fetch_add(1, Ordering::Relaxed)` at the
//!      event site.
//!   3. Exposing `metrics.render_prometheus()` over a tiny HTTP
//!      endpoint — see `gptl-node`'s `--metrics-addr` flag for the
//!      reference implementation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── RelayMetrics (gptl-node) ────────────────────────────────────────────────

/// Counters for a single relay-node process.
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Total TCP accepts since startup.
    pub connections_total: AtomicU64,
    /// Total successful ntor-lite handshakes.
    pub handshakes_total: AtomicU64,
    /// Total handshake failures (timeout, malformed cell, bad pubkey).
    pub handshakes_failed_total: AtomicU64,
    /// Connections rejected because `MAX_CIRCUITS` was reached.
    pub circuits_rejected_total: AtomicU64,
    /// Currently active circuits — gauge, not a counter.
    pub active_circuits: AtomicU64,
    /// Total RELAY_BEGIN cells that opened a destination stream.
    pub streams_opened_total: AtomicU64,
    /// Total RELAY_BEGIN cells rejected by the exit policy
    /// (private address, blocked port, max-streams).
    pub streams_blocked_total: AtomicU64,
    /// Total RELAY_EXTEND requests honored (multi-hop hop count).
    pub extends_total: AtomicU64,
    /// Total RELAY_EXTEND failures (connect to relay2 failed, etc.).
    pub extends_failed_total: AtomicU64,
}

impl RelayMetrics {
    /// Wrap a freshly-initialised metrics struct in an `Arc` for
    /// sharing across the relay loop's tasks.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Render all counters in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        push_counter(
            &mut out,
            "gptl_node_connections_total",
            "Total TCP connections accepted by this relay since startup.",
            self.connections_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_handshakes_total",
            "Total successful ntor-lite handshakes.",
            self.handshakes_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_handshakes_failed_total",
            "Total handshake failures (timeout, malformed CREATE, bad pubkey).",
            self.handshakes_failed_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_circuits_rejected_total",
            "Connections rejected because the per-process circuit cap was reached.",
            self.circuits_rejected_total.load(Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "gptl_node_active_circuits",
            "Number of circuits currently being served.",
            self.active_circuits.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_streams_opened_total",
            "Total exit streams opened (RELAY_BEGIN honored).",
            self.streams_opened_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_streams_blocked_total",
            "Total RELAY_BEGIN cells refused by the exit policy.",
            self.streams_blocked_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_extends_total",
            "Total RELAY_EXTEND requests that successfully built a second hop.",
            self.extends_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_node_extends_failed_total",
            "Total RELAY_EXTEND failures (connect to relay2 failed, etc.).",
            self.extends_failed_total.load(Ordering::Relaxed),
        );
        out
    }
}

// ── ClientMetrics (gptl-client) ─────────────────────────────────────────────

/// Counters for a single SOCKS5 client process.
#[derive(Debug, Default)]
pub struct ClientMetrics {
    /// Total SOCKS5 connections accepted.
    pub socks5_accepted_total: AtomicU64,
    /// Total SOCKS5 negotiations that completed (CONNECT request parsed).
    pub socks5_completed_total: AtomicU64,
    /// Total successful circuit construction events.
    pub circuits_built_total: AtomicU64,
    /// Total circuit construction failures.
    pub circuits_failed_total: AtomicU64,
    /// Currently active circuits.
    pub active_circuits: AtomicU64,
    /// Total stream begins that succeeded end-to-end.
    pub streams_succeeded_total: AtomicU64,
    /// Total stream begins that the relay rejected (BeginFailed).
    pub streams_rejected_total: AtomicU64,
    /// Total connect timeouts (relay didn't send CONNECTED in time).
    pub stream_timeouts_total: AtomicU64,
    /// Relays the startup self-test marked healthy on the most recent run.
    pub selftest_healthy_relays: AtomicU64,
    /// Relays the startup self-test marked unhealthy on the most recent run.
    pub selftest_unhealthy_relays: AtomicU64,
}

impl ClientMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        push_counter(
            &mut out,
            "gptl_client_socks5_accepted_total",
            "Total SOCKS5 TCP connections accepted on the listen socket.",
            self.socks5_accepted_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_socks5_completed_total",
            "Total SOCKS5 CONNECT requests that completed negotiation.",
            self.socks5_completed_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_circuits_built_total",
            "Total circuits successfully constructed.",
            self.circuits_built_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_circuits_failed_total",
            "Total circuit-construction failures.",
            self.circuits_failed_total.load(Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "gptl_client_active_circuits",
            "Number of circuits currently in use.",
            self.active_circuits.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_streams_succeeded_total",
            "Total destination streams that completed end-to-end.",
            self.streams_succeeded_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_streams_rejected_total",
            "Total destination streams that the relay rejected (exit policy / NXDOMAIN).",
            self.streams_rejected_total.load(Ordering::Relaxed),
        );
        push_counter(
            &mut out,
            "gptl_client_stream_timeouts_total",
            "Total destination connect timeouts.",
            self.stream_timeouts_total.load(Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "gptl_client_selftest_healthy_relays",
            "Relays marked healthy on the most recent startup self-test.",
            self.selftest_healthy_relays.load(Ordering::Relaxed),
        );
        push_gauge(
            &mut out,
            "gptl_client_selftest_unhealthy_relays",
            "Relays marked unhealthy on the most recent startup self-test.",
            self.selftest_unhealthy_relays.load(Ordering::Relaxed),
        );
        out
    }
}

// ── ClientMetrics CircuitObserver impl ──────────────────────────────────────

/// Adapter so a [`ClientMetrics`] handle can be plugged into the
/// proxy's observer slot.  Ticks the corresponding counters and
/// active-circuits gauge on each event.
#[derive(Debug)]
pub struct MetricsObserver {
    metrics: Arc<ClientMetrics>,
}

impl MetricsObserver {
    pub fn new(metrics: Arc<ClientMetrics>) -> Self {
        Self { metrics }
    }
}

impl crate::observer::CircuitObserver for MetricsObserver {
    fn register(&self, _circuit_id: u32, _relay_label: &str) {
        self.metrics
            .circuits_built_total
            .fetch_add(1, Ordering::Relaxed);
        self.metrics.active_circuits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_success(&self, _circuit_id: u32, _latency: std::time::Duration, _bytes: u64) {
        self.metrics
            .streams_succeeded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    fn record_failure(&self, _circuit_id: u32, kind: crate::observer::FailureKind, _reason: &str) {
        use crate::observer::FailureKind::*;
        match kind {
            Handshake | Extend => {
                self.metrics
                    .circuits_failed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            Stream => {
                self.metrics
                    .streams_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            CircuitDrop | Other => {
                self.metrics
                    .circuits_failed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn unregister(&self, _circuit_id: u32) {
        // saturating sub: never go below zero even if register/unregister
        // counts somehow drift.
        let prev = self.metrics.active_circuits.load(Ordering::Relaxed);
        if prev > 0 {
            self.metrics.active_circuits.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} counter", name);
    let _ = writeln!(out, "{} {}", name, value);
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {} {}", name, help);
    let _ = writeln!(out, "# TYPE {} gauge", name);
    let _ = writeln!(out, "{} {}", name, value);
}

// ── Tiny HTTP server ────────────────────────────────────────────────────────

/// Run a minimal HTTP server on `addr` that responds to GET /metrics
/// with the result of `render()`.  Anything else returns 404.
///
/// The server is intentionally hand-rolled (no hyper, no axum) so the
/// metrics surface doesn't drag a heavy HTTP stack into a binary
/// otherwise meant to be tiny.  HTTP/1.0 request parsing only — we
/// read until `\r\n\r\n`, look at the first request line, and stream
/// a fixed response.  This is fine for a localhost-or-LAN /metrics
/// endpoint; do NOT expose it to the public internet.
pub async fn serve_metrics<F>(addr: std::net::SocketAddr, render: F) -> Result<(), std::io::Error>
where
    F: Fn() -> String + Send + Sync + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let render = Arc::new(render);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("metrics endpoint listening on http://{}/metrics", addr);

    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let render = Arc::clone(&render);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut total = 0usize;
            // Read until we see the end-of-headers sentinel or hit the
            // buffer cap (no legitimate GET /metrics request is bigger
            // than ~256 bytes).
            loop {
                if total >= buf.len() {
                    break;
                }
                match stream.read(&mut buf[total..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total += n;
                        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }

            let head = std::str::from_utf8(&buf[..total]).unwrap_or("");
            let first_line = head.lines().next().unwrap_or("");
            let mut parts = first_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");

            let body = if method == "GET" && (path == "/metrics" || path.starts_with("/metrics?")) {
                render()
            } else {
                let _ = stream
                    .write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return;
            };

            let response = format!(
                "HTTP/1.0 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[test]
    fn test_relay_metrics_render_format() {
        let m = RelayMetrics::default();
        m.handshakes_total.fetch_add(7, Ordering::Relaxed);
        m.active_circuits.store(3, Ordering::Relaxed);

        let text = m.render_prometheus();
        // Counter exposition.
        assert!(text.contains("# TYPE gptl_node_handshakes_total counter"));
        assert!(text.contains("gptl_node_handshakes_total 7"));
        // Gauge exposition.
        assert!(text.contains("# TYPE gptl_node_active_circuits gauge"));
        assert!(text.contains("gptl_node_active_circuits 3"));
        // Default-zero counters still appear.
        assert!(text.contains("gptl_node_circuits_rejected_total 0"));
    }

    #[test]
    fn test_client_metrics_render_format() {
        let m = ClientMetrics::default();
        m.circuits_built_total.store(42, Ordering::Relaxed);
        m.selftest_healthy_relays.store(2, Ordering::Relaxed);

        let text = m.render_prometheus();
        assert!(text.contains("gptl_client_circuits_built_total 42"));
        assert!(text.contains("gptl_client_selftest_healthy_relays 2"));
    }

    #[tokio::test]
    async fn test_serve_metrics_returns_render_on_get_slash_metrics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        // Launch the server, give it a moment to bind.
        tokio::spawn(async move {
            let _ = serve_metrics(addr, || "hello-metrics".to_string()).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);

        assert!(text.starts_with("HTTP/1.0 200 OK"), "got: {}", text);
        assert!(text.contains("hello-metrics"));
    }

    #[tokio::test]
    async fn test_serve_metrics_404_on_other_paths() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        tokio::spawn(async move {
            let _ = serve_metrics(addr, || "irrelevant".to_string()).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /foo HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.0 404"));
    }
}
