//! GPTL relay node — thin wrapper around [`gptl_transport::relay_node::RelayNode`].
//!
//! All the cell-protocol logic now lives in the library so it can be
//! shared with `secure-relay` and unit-tested in-process.  This binary
//! handles: CLI parsing, key persistence, descriptor printing, logging
//! setup, and binding the listener.
//!
//! # Usage
//!
//!   gptl-node [OPTIONS]
//!
//! # Options
//!
//!   --key <PATH>             Path to private key file (hex, 32 bytes).
//!                             If absent, a new key is generated (ephemeral).
//!   --listen <ADDR>          Address to accept connections on (default: 0.0.0.0:9001)
//!   --nickname <NAME>        Human-readable relay name (default: hostname)
//!   --print-descriptor       Print a JSON relay descriptor and exit
//!   --log <LEVEL>            Log level: error|warn|info|debug|trace (default: info)
//!   --allow-private          (testing only) permit loopback / RFC1918 destinations
//!   --max-circuits <N>       Override the per-process circuit cap (default: 1000)

use gptl_transport::{
    bootstrap::{BootstrapConfig, RelayDescriptor},
    handshake::RelayStaticKey,
    metrics::serve_metrics,
    relay_node::{RelayNode, RelayOptions},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    let args = parse_args();
    init_logging(&args.log_level);

    let static_key = load_or_generate_key(args.key_path.as_deref());
    info!("relay fingerprint: {}", hex::encode(static_key.fingerprint));
    info!("relay pubkey:      {}", hex::encode(static_key.public));

    // Persist a freshly-generated key BEFORE anything else (including
    // --print-descriptor), so the descriptor we publish matches the key the
    // relay will actually serve with on subsequent runs. Otherwise
    // `gptl-node --key <path> --print-descriptor` (per the usage example) would
    // print a throwaway key and the relay would later generate a different one.
    if let Some(ref path) = args.key_path {
        if !path.exists() {
            persist_key(&static_key, path);
        }
    }

    if args.print_descriptor {
        let desc = RelayDescriptor {
            nickname: args.nickname.clone(),
            address: descriptor_address(args.listen),
            pubkey_hex: hex::encode(static_key.public),
        };
        let config = BootstrapConfig { relays: vec![desc] };
        println!("{}", serde_json::to_string_pretty(&config).unwrap());
        return;
    }

    if args.allow_private {
        warn!(
            "--allow-private is set: relay will permit loopback/RFC1918 \
             destinations.  For local testing ONLY — never use in production."
        );
    }

    let listener = TcpListener::bind(args.listen).await.unwrap_or_else(|e| {
        eprintln!("error: bind {}: {}", args.listen, e);
        std::process::exit(1);
    });
    info!(
        "GPTL relay '{}' listening on {}",
        args.nickname, args.listen
    );

    let mut options = RelayOptions::default().with_allow_private(args.allow_private);
    if let Some(cap) = args.max_circuits {
        options = options.with_max_circuits(cap);
    }
    let node = Arc::new(RelayNode::new(static_key, options));

    // Optional Prometheus /metrics endpoint.  Bound to whatever the
    // operator passed in `--metrics-addr`; defaults to disabled.
    if let Some(metrics_addr) = args.metrics_addr {
        let m = node.metrics();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(metrics_addr, move || m.render_prometheus()).await {
                tracing::error!("metrics endpoint error: {}", e);
            }
        });
    }

    if let Err(e) = node.run(listener).await {
        eprintln!("relay error: {}", e);
        std::process::exit(1);
    }
}

// ── Argument parsing ──────────────────────────────────────────────────────────

struct Args {
    key_path: Option<PathBuf>,
    listen: SocketAddr,
    nickname: String,
    print_descriptor: bool,
    log_level: String,
    allow_private: bool,
    max_circuits: Option<usize>,
    metrics_addr: Option<SocketAddr>,
}

fn parse_args() -> Args {
    let mut key_path: Option<PathBuf> = None;
    let mut listen: SocketAddr = "0.0.0.0:9001".parse().unwrap();
    let mut nickname = hostname_or_default();
    let mut print_descriptor = false;
    let mut log_level = "info".to_string();
    let mut allow_private = false;
    let mut max_circuits: Option<usize> = None;
    let mut metrics_addr: Option<SocketAddr> = None;

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--key" => {
                key_path = Some(PathBuf::from(next_arg(&arg, &mut iter)));
            }
            "--listen" => {
                let val = next_arg(&arg, &mut iter);
                listen = val.parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid listen address '{}'", val);
                    std::process::exit(1);
                });
            }
            "--nickname" => {
                nickname = next_arg(&arg, &mut iter);
            }
            "--print-descriptor" => {
                print_descriptor = true;
            }
            "--log" => {
                log_level = next_arg(&arg, &mut iter);
            }
            "--allow-private" => {
                allow_private = true;
            }
            "--max-circuits" => {
                let val = next_arg(&arg, &mut iter);
                max_circuits = Some(val.parse::<usize>().unwrap_or_else(|_| {
                    eprintln!("error: --max-circuits requires a positive integer");
                    std::process::exit(1);
                }));
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
                std::process::exit(1);
            }
        }
    }

    Args {
        key_path,
        listen,
        nickname,
        print_descriptor,
        log_level,
        allow_private,
        max_circuits,
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
    println!("gptl-node — GPTL relay node");
    println!();
    println!("USAGE:");
    println!("  gptl-node [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("  --key <PATH>             Path to 32-byte hex private key file");
    println!("  --listen <ADDR>          Listen address (default: 0.0.0.0:9001)");
    println!("  --nickname <NAME>        Relay display name");
    println!("  --print-descriptor       Print JSON descriptor and exit");
    println!("  --log <LEVEL>            Log level (default: info)");
    println!("  --allow-private          (testing only) permit loopback / RFC1918 destinations");
    println!("  --max-circuits <N>       Override the per-process circuit cap (default: 1000)");
    println!(
        "  --metrics-addr <ADDR>    Bind a Prometheus /metrics endpoint here (e.g. 127.0.0.1:9100)"
    );
    println!("  -h, --help               Print this help");
    println!();
    println!("EXAMPLE:");
    println!("  gptl-node --key /etc/gptl/relay.key --print-descriptor");
}

// ── Key management ────────────────────────────────────────────────────────────

fn load_or_generate_key(path: Option<&std::path::Path>) -> RelayStaticKey {
    if let Some(p) = path {
        if p.exists() {
            let hex = std::fs::read_to_string(p).unwrap_or_else(|e| {
                eprintln!("error reading key {}: {}", p.display(), e);
                std::process::exit(1);
            });
            let bytes = hex::decode(hex.trim()).unwrap_or_else(|e| {
                eprintln!("error decoding key hex: {}", e);
                std::process::exit(1);
            });
            if bytes.len() != 32 {
                eprintln!("error: key file must be 32 bytes (64 hex chars)");
                std::process::exit(1);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return RelayStaticKey::from_bytes(arr);
        }
    }
    let key = RelayStaticKey::generate();
    eprintln!("generated new relay key; use --key <PATH> to persist it");
    key
}

fn persist_key(key: &RelayStaticKey, path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let hex = hex::encode(*key.private);
    std::fs::write(path, &hex).unwrap_or_else(|e| {
        warn!("could not save key to {}: {}", path.display(), e);
    });
    info!("saved new key to {}", path.display());
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn hostname_or_default() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "gptl-relay".to_string())
}

/// Best-effort externally-routable IP for the descriptor.  Respects the
/// caller's listen address: if they explicitly bound a non-wildcard IP
/// (e.g. `127.0.0.1` for a local test, or a specific NIC), advertise THAT
/// — clients reading the descriptor won't be able to reach a wildcard
/// hint.  Only fall back to the UDP egress probe when the bind is a
/// wildcard (`0.0.0.0` / `::`).
fn descriptor_address(listen: SocketAddr) -> String {
    let ip = listen.ip();
    if ip.is_unspecified() {
        format!(
            "{}:{}",
            egress_ip_probe().unwrap_or_else(|| ip.to_string()),
            listen.port()
        )
    } else {
        listen.to_string()
    }
}

fn egress_ip_probe() -> Option<String> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    s.local_addr().ok().map(|a| a.ip().to_string())
}

fn init_logging(level: &str) {
    use std::str::FromStr;
    let filter = tracing_subscriber::filter::LevelFilter::from_str(level)
        .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        // Write logs to stderr so stdout stays clean for machine-readable output
        // (e.g. `gptl-node --print-descriptor > relays.json`).
        .with_writer(std::io::stderr)
        .init();
}
