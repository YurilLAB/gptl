//! gptl-authority — generate a directory authority key and sign relay directories.
//!
//! The relay directory (`relays.json`) is the root of trust: clients connect to
//! whatever relays it lists. Signing it with an authority key — and pinning the
//! authority public key on the client (`gptl-client --authority-key <HEX>`) —
//! prevents a tampered directory from substituting attacker-controlled relays.
//!
//! # Usage
//!
//!   gptl-authority keygen
//!       Generate an ed25519 authority keypair (prints private + public hex).
//!
//!   gptl-authority sign --key <PRIV_HEX> --relays <relays.json> [--out <PATH>]
//!       Sign an unsigned directory ({"relays":[...]}) and emit a signed one
//!       (to stdout, or to --out). Distribute the public key to clients.

use gptl_transport::bootstrap::{BootstrapConfig, SignedDirectory};
use std::path::PathBuf;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  \
                 gptl-authority keygen\n  \
                 gptl-authority sign --key <PRIV_HEX> --relays <relays.json> [--out <PATH>]"
            );
            exit(2);
        }
    }
}

fn keygen() {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    // stdout: the public key (safe to distribute / pin on clients).
    // stderr: the private key (secret — keep it offline).
    eprintln!(
        "authority PRIVATE key (KEEP SECRET): {}",
        hex::encode(sk.to_bytes())
    );
    println!("{}", hex::encode(sk.verifying_key().to_bytes()));
    eprintln!("(public key printed to stdout; pin it on clients with --authority-key)");
}

fn sign(args: &[String]) {
    let mut key_hex: Option<String> = None;
    let mut relays_path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--key" => key_hex = it.next().cloned(),
            "--relays" => relays_path = it.next().map(PathBuf::from),
            "--out" => out_path = it.next().map(PathBuf::from),
            other => {
                eprintln!("error: unknown argument '{}'", other);
                exit(2);
            }
        }
    }

    let key_hex = key_hex.unwrap_or_else(|| {
        eprintln!("error: --key <PRIV_HEX> is required");
        exit(2);
    });
    let relays_path = relays_path.unwrap_or_else(|| {
        eprintln!("error: --relays <relays.json> is required");
        exit(2);
    });

    let seed = hex::decode(key_hex.trim()).unwrap_or_else(|e| {
        eprintln!("error: invalid --key hex: {}", e);
        exit(1);
    });
    let seed: [u8; 32] = seed.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("error: --key must be a 32-byte (64 hex char) ed25519 private key");
        exit(1);
    });
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let cfg = BootstrapConfig::from_json_file(&relays_path).unwrap_or_else(|e| {
        eprintln!("error: load {}: {}", relays_path.display(), e);
        exit(1);
    });
    if let Err(e) = cfg.validate() {
        eprintln!("error: directory invalid: {}", e);
        exit(1);
    }

    let signed = SignedDirectory::sign(cfg.relays, &signing_key);
    let json = serde_json::to_string_pretty(&signed).expect("serialize signed directory");

    match out_path {
        Some(path) => {
            std::fs::write(&path, json).unwrap_or_else(|e| {
                eprintln!("error: write {}: {}", path.display(), e);
                exit(1);
            });
            eprintln!("signed directory written to {}", path.display());
            eprintln!(
                "authority public key: {}",
                hex::encode(signing_key.verifying_key().to_bytes())
            );
        }
        None => println!("{}", json),
    }
}
