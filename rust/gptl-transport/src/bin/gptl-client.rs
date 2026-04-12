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
//!   --relays <PATH>      Path to relays.json (default: ~/.config/gptl/relays.json)
//!   --listen <ADDR>      SOCKS5 listen address (default: 127.0.0.1:1080)
//!   --log <LEVEL>        Log level: error|warn|info|debug|trace (default: info)

use gptl_transport::{
    bootstrap::{default_bootstrap_path, BootstrapConfig},
    proxy::{run as run_proxy, ProxyConfig},
    TransportError,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

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

    let config = ProxyConfig {
        listen_addr: args.listen,
        bootstrap: Arc::new(bootstrap),
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
}

fn parse_args() -> Args {
    let mut relays: Option<PathBuf> = None;
    let mut listen: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let mut log_level = "info".to_string();

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

    Args { relays, listen, log_level }
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
    println!("  --relays <PATH>   Path to relays.json  (default: ~/.config/gptl/relays.json)");
    println!("  --listen <ADDR>   SOCKS5 listen address (default: 127.0.0.1:1080)");
    println!("  --log <LEVEL>     Log level: error|warn|info|debug|trace (default: info)");
    println!("  -h, --help        Print this help");
    println!();
    println!("EXAMPLE:");
    println!("  gptl-client --relays /etc/gptl/relays.json --listen 127.0.0.1:1080");
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
