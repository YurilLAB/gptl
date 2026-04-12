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
    path::PathConfig,
    proxy::{run as run_proxy, ProxyConfig},
    TransportError,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
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
        tracing::info!(
            "guard manager initialized from {}",
            guards_path.display()
        );
        Some(Arc::new(Mutex::new(gm)))
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
        tracing::info!("circuit pool manager started (target size: {})", args.pool_size);
        // Keep the handle alive; leak it intentionally (process will exit on error anyway).
        std::mem::forget(handle);
        Some(manager)
    } else {
        None
    };

    let config = ProxyConfig {
        listen_addr: args.listen,
        bootstrap,
        hop_count: args.hop_count,
        pool_manager,
        guard_manager,
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
}

fn parse_args() -> Args {
    let mut relays: Option<PathBuf> = None;
    let mut listen: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut log_level = "info".to_string();
    let mut hop_count: usize = 1;
    let mut guards: Option<PathBuf> = None;
    let mut pool_size: usize = 0;
    let mut guard_rotation_days: u64 = 30;

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

    Args { relays, listen, log_level, hop_count, guards, pool_size, guard_rotation_days }
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
    println!("  --relays <PATH>             Path to relays.json  (default: ~/.config/gptl/relays.json)");
    println!("  --listen <ADDR>             SOCKS5 listen address (default: 127.0.0.1:1080)");
    println!("  --hops <N>                  Number of hops: 1 (single) or 2 (two-hop, default: 1)");
    println!("  --guards <PATH>             Path to guards.json for persistent guard state");
    println!("  --pool-size <N>             Pre-build N circuits (0 = disabled, default: 0)");
    println!("  --guard-rotation-days <N>   Guard rotation interval in days (default: 30)");
    println!("  --log <LEVEL>               Log level: error|warn|info|debug|trace (default: info)");
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
