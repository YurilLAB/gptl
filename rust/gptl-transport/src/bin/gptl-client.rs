//! GPTL client — SOCKS5 proxy entry point.
//!
//! Loads the bootstrap relay directory and listens for SOCKS5 connections.
//!
//! # Usage
//!
//!   gptl-client [OPTIONS]
//!
//! # Options
//!
//!   --relays <PATH>             Path to relays.json (default: ~/.config/gptl/relays.json)
//!   --listen <ADDR>             SOCKS5 listen address (default: 127.0.0.1:1080)
//!   --hops <N>                  Number of hops: 1 or 2 (default: 1)
//!   --guards <PATH>             Path to guards.json for persistent guard state
//!   --pool-size <N>             Pre-build N circuits (0 = disabled, default: 0)
//!   --guard-rotation-days <N>   Guard rotation interval in days (default: 30)
//!   --log <LEVEL>               Log level: error|warn|info|debug|trace (default: info)

use gptl_transport::{
    bootstrap::{default_bootstrap_path, BootstrapConfig},
    circuit_pool::{CircuitPoolManager, PoolConfig},
    guard::{GuardConfig, GuardManager},
    metrics::{serve_metrics, ClientMetrics, MetricsObserver},
    observer::{CompositeObserver, SharedObserver},
    path::PathConfig,
    proxy::{run as run_proxy, ProxyConfig},
    selftest, TransportError,
};
use std::sync::atomic::Ordering;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    let args = parse_args();
    init_logging(&args.log_level);

    let relays_path = args.relays.unwrap_or_else(|| {
        default_bootstrap_path()
            .expect("could not determine config directory; pass --relays <PATH>")
    });

    let bootstrap = match BootstrapConfig::from_json_file(&relays_path) {
        Ok(b) => b,
        Err(TransportError::Bootstrap(e)) => {
            eprintln!("error: {}", e);
            eprintln!(
                "hint: create {} with at least one relay entry (see gptl-node --print-descriptor)",
                relays_path.display()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error loading relay directory: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = bootstrap.validate() {
        eprintln!("relay directory invalid: {}", e);
        std::process::exit(1);
    }

    tracing::info!(
        "loaded {} relay(s) from {}",
        bootstrap.relays.len(),
        relays_path.display()
    );

    // ── Metrics infrastructure ───────────────────────────────────────────────
    // Always allocate the counters even when `--metrics-addr` is unset
    // so the observer wiring stays uniform (and a future control-plane
    // tool can read them via FFI).  Serve them only when bound.
    let client_metrics = ClientMetrics::new();
    if let Some(addr) = args.metrics_addr {
        let m = Arc::clone(&client_metrics);
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(addr, move || m.render_prometheus()).await {
                tracing::error!("metrics endpoint error: {}", e);
            }
        });
    }

    // ── Startup self-test ────────────────────────────────────────────────────
    // Probe every relay (TCP connect + ntor-lite handshake) BEFORE
    // claiming the proxy is ready.  We refuse to start with zero healthy
    // relays — without one, the very first SOCKS5 request would fail in
    // a confusing way far from this code.  Skip when --skip-selftest is set.
    if !args.skip_selftest {
        let timeout = Duration::from_secs(args.selftest_timeout_secs);
        tracing::info!(
            "running startup self-test against {} relay(s) (timeout {}s)…",
            bootstrap.relays.len(),
            args.selftest_timeout_secs
        );
        let results = selftest::probe_all(&bootstrap.relays, timeout).await;
        let summary = selftest::format_summary(&results);
        // One log call so it always prints as a single block.
        tracing::info!("{}", summary);

        let healthy = results.iter().filter(|r| r.outcome.is_healthy()).count();
        let unhealthy = results.len() - healthy;
        client_metrics
            .selftest_healthy_relays
            .store(healthy as u64, Ordering::Relaxed);
        client_metrics
            .selftest_unhealthy_relays
            .store(unhealthy as u64, Ordering::Relaxed);
        if healthy == 0 {
            eprintln!(
                "error: startup self-test found ZERO healthy relays — refusing to start.\n\
                 hint: check that gptl-node is running at the addresses in {}, that the\n\
                 hint: pubkey_hex values match, and that the listen address is reachable.\n\
                 hint: re-run with --skip-selftest to bypass this gate.",
                relays_path.display()
            );
            std::process::exit(1);
        }
        if healthy < bootstrap.relays.len() {
            tracing::warn!(
                "self-test: {} relay(s) failed — proceeding with the {} that passed",
                bootstrap.relays.len() - healthy,
                healthy
            );
        }
    } else {
        tracing::warn!("startup self-test SKIPPED (--skip-selftest)");
    }

    let bootstrap = Arc::new(bootstrap);

    // ── Guard manager (optional) ──────────────────────────────────────────────
    let guard_manager = if let Some(ref guards_path) = args.guards {
        let guard_config = GuardConfig {
            rotation_days: args.guard_rotation_days,
            ..Default::default()
        };
        let mut gm = GuardManager::new(guard_config, Some(guards_path.clone()));
        if let Err(e) = gm.initialize(&bootstrap.relays).await {
            eprintln!("error initializing guard manager: {}", e);
            std::process::exit(1);
        }
        // Initial save so a fresh selection survives an immediate restart.
        if let Err(e) = gm.save().await {
            tracing::warn!("guard state initial save failed: {}", e);
        }
        tracing::info!(
            "guard manager initialized from {} ({} guards, rotation every {}d)",
            guards_path.display(),
            gm.guard_set().guard_count(),
            args.guard_rotation_days,
        );
        let gm = Arc::new(Mutex::new(gm));

        // Periodic flusher — guard mutations from report_success/report_failure
        // are in-memory only, so without this every restart loses the
        // success/failure history accumulated during the previous session.
        // 30s is short enough that at most one circuit-build's worth of
        // state is lost on a crash, and the lock is held for milliseconds
        // (just the JSON serialize + fsync).
        let flusher_gm = Arc::clone(&gm);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            // Skip the immediate first tick; we already saved above.
            tick.tick().await;
            loop {
                tick.tick().await;
                let gm = flusher_gm.lock().await;
                if let Err(e) = gm.save().await {
                    tracing::warn!("periodic guard state save failed: {}", e);
                }
            }
        });

        Some(gm)
    } else {
        None
    };

    // ── Circuit pool manager (optional) ───────────────────────────────────────
    let pool_manager = if args.pool_size > 0 {
        let pool_config = PoolConfig {
            size: args.pool_size,
            ..Default::default()
        };
        let path_config = PathConfig {
            num_hops: args.hop_count,
            exclude_same_subnet: true,
            exclude_same_nickname_prefix: true,
        };
        // Build a path selector for the pool; guard is wired via guard_config below.
        let guard_config = args.guards.as_ref().map(|_| GuardConfig {
            rotation_days: args.guard_rotation_days,
            ..Default::default()
        });
        let guard_path = args.guards.clone();
        let manager = Arc::new(CircuitPoolManager::new(
            pool_config,
            path_config,
            Arc::clone(&bootstrap),
            guard_config,
            guard_path,
        ));
        // Start the maintenance task; it will trigger the first pool refill.
        let handle = Arc::clone(&manager).start_maintenance();
        // Give the maintenance task a moment to build initial circuits.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        tracing::info!(
            "circuit pool manager started (target size: {})",
            args.pool_size
        );
        // Keep the handle alive; leak it intentionally (process will exit on error anyway).
        std::mem::forget(handle);
        Some(manager)
    } else {
        None
    };

    // Build the observer.  Today it's just the metrics observer; the
    // composite is here so future installers (e.g. a routing-layer
    // bridge) can be added without touching the proxy wiring again.
    let observer: SharedObserver = Arc::new(
        CompositeObserver::new()
            .push(Arc::new(MetricsObserver::new(Arc::clone(&client_metrics))) as SharedObserver),
    );

    let config = ProxyConfig {
        listen_addr: args.listen,
        bootstrap,
        hop_count: args.hop_count,
        pool_manager,
        guard_manager,
        observer,
        metrics: Some(Arc::clone(&client_metrics)),
    };

    if let Err(e) = run_proxy(config).await {
        eprintln!("proxy error: {}", e);
        std::process::exit(1);
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────────

struct Args {
    relays: Option<PathBuf>,
    listen: SocketAddr,
    log_level: String,
    hop_count: usize,
    guards: Option<PathBuf>,
    pool_size: usize,
    guard_rotation_days: u64,
    skip_selftest: bool,
    selftest_timeout_secs: u64,
    metrics_addr: Option<SocketAddr>,
}

fn parse_args() -> Args {
    let mut relays: Option<PathBuf> = None;
    let mut listen: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut log_level = "info".to_string();
    let mut hop_count: usize = 1;
    let mut guards: Option<PathBuf> = None;
    let mut pool_size: usize = 0;
    let mut guard_rotation_days: u64 = 30;
    let mut skip_selftest = false;
    let mut selftest_timeout_secs: u64 = 5;
    let mut metrics_addr: Option<SocketAddr> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--relays" => {
                let val = next_arg(&arg, &mut iter);
                relays = Some(PathBuf::from(val));
            }
            "--listen" => {
                let val = next_arg(&arg, &mut iter);
                listen = val.parse::<SocketAddr>().unwrap_or_else(|_| {
                    eprintln!("error: invalid listen address '{}'", val);
                    std::process::exit(1);
                });
            }
            "--hops" => {
                let val = next_arg(&arg, &mut iter);
                hop_count = val.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("error: invalid hop count '{}' (must be 1 or 2)", val);
                    std::process::exit(1);
                });
                if hop_count == 0 || hop_count > 2 {
                    eprintln!("error: hop count must be 1 or 2 (got {})", hop_count);
                    std::process::exit(1);
                }
            }
            "--guards" => {
                let val = next_arg(&arg, &mut iter);
                guards = Some(PathBuf::from(val));
            }
            "--pool-size" => {
                let val = next_arg(&arg, &mut iter);
                pool_size = val.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("error: invalid pool size '{}'", val);
                    std::process::exit(1);
                });
            }
            "--guard-rotation-days" => {
                let val = next_arg(&arg, &mut iter);
                guard_rotation_days = val.parse::<u64>().unwrap_or_else(|_| {
                    eprintln!("error: invalid guard rotation days '{}'", val);
                    std::process::exit(1);
                });
            }
            "--log" => {
                log_level = next_arg(&arg, &mut iter);
            }
            "--skip-selftest" => {
                skip_selftest = true;
            }
            "--selftest-timeout" => {
                let val = next_arg(&arg, &mut iter);
                selftest_timeout_secs = val.parse::<u64>().unwrap_or_else(|_| {
                    eprintln!("error: invalid --selftest-timeout '{}'", val);
                    std::process::exit(1);
                });
                if selftest_timeout_secs == 0 {
                    eprintln!("error: --selftest-timeout must be > 0");
                    std::process::exit(1);
                }
            }
            "--metrics-addr" => {
                let val = next_arg(&arg, &mut iter);
                metrics_addr = Some(val.parse::<SocketAddr>().unwrap_or_else(|_| {
                    eprintln!("error: invalid --metrics-addr '{}'", val);
                    std::process::exit(1);
                }));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            unknown => {
                eprintln!("error: unknown argument '{}'", unknown);
                eprintln!("Run with --help for usage.");
                std::process::exit(1);
            }
        }
    }

    Args {
        relays,
        listen,
        log_level,
        hop_count,
        guards,
        pool_size,
        guard_rotation_days,
        skip_selftest,
        selftest_timeout_secs,
        metrics_addr,
    }
}

fn next_arg(flag: &str, iter: &mut impl Iterator<Item = String>) -> String {
    iter.next().unwrap_or_else(|| {
        eprintln!("error: '{}' requires a value", flag);
        std::process::exit(1);
    })
}

fn print_usage() {
    println!("gptl-client — GPTL SOCKS5 proxy");
    println!();
    println!("USAGE:");
    println!("  gptl-client [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!(
        "  --relays <PATH>             Path to relays.json  (default: ~/.config/gptl/relays.json)"
    );
    println!("  --listen <ADDR>             SOCKS5 listen address (default: 127.0.0.1:1080)");
    println!("  --hops <N>                  Number of hops: 1 (single) or 2 (two-hop, default: 1)");
    println!("  --guards <PATH>             Path to guards.json for persistent guard state");
    println!("  --pool-size <N>             Pre-build N circuits (0 = disabled, default: 0)");
    println!("  --guard-rotation-days <N>   Guard rotation interval in days (default: 30)");
    println!("  --skip-selftest             Skip the startup self-test (NOT recommended)");
    println!("  --selftest-timeout <SECS>   Per-relay self-test timeout (default: 5)");
    println!(
        "  --metrics-addr <ADDR>       Bind a Prometheus /metrics endpoint here (e.g. 127.0.0.1:9101)"
    );
    println!(
        "  --log <LEVEL>               Log level: error|warn|info|debug|trace (default: info)"
    );
    println!("  -h, --help                  Print this help");
    println!();
    println!("EXAMPLE:");
    println!("  gptl-client --relays /etc/gptl/relays.json --listen 127.0.0.1:1080");
    println!("  gptl-client --relays relays.json --guards /var/lib/gptl/guards.json --pool-size 3");
}

fn init_logging(level: &str) {
    use std::str::FromStr;
    let filter = tracing_subscriber::filter::LevelFilter::from_str(level)
        .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();
}
