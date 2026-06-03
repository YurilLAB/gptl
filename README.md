# GPTL - General Purpose Transport Layer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A next-generation anonymity network with comprehensive defenses against modern attacks on Tor, I2P, and VPN systems.

## Overview

GPTL implements cutting-edge countermeasures against 10 major attack categories identified in academic research from 2005-2024:

1. **Traffic Confirmation Attacks** (Murdoch-Danezis, 2005)
2. **Website Fingerprinting** (Panchenko et al., 2011-2016)
3. **Circuit Fingerprinting** (Kwon et al., 2015)
4. **Guard Discovery Attacks** (Overlier-Syverson, 2006)
5. **Sniper Attacks** (Resource Exhaustion) (Jansen et al., 2014)
6. **Sybil Attacks** (Biryukov et al., 2013)
7. **BGP Hijacking Attacks** (RAPTOR) (Sun et al., 2015)
8. **Timing Attacks**
9. **DNS Leakage**
10. **WebRTC Leakage**

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                        │
│  - WebRTC Guard    - DNS Guard    - Protocol Hardening      │
├─────────────────────────────────────────────────────────────┤
│                    CIRCUIT LAYER                            │
│  - Circuit Shield  - Vanguards    - Guard Armor             │
├─────────────────────────────────────────────────────────────┤
│                    ROUTING LAYER                            │
│  - BGP Guard       - AS-Aware Selection    - Multi-Path     │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER                          │
│  - Timing Shield   - Traffic Shaping    - Adaptive Padding  │
├─────────────────────────────────────────────────────────────┤
│                    RESOURCE LAYER                           │
│  - Resource Guard  - Sybil Shield    - Rate Limiting        │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Cargo

### Building

```bash
cd rust
cargo build --release
```

### Running Tests

```bash
cd rust
cargo test
```

## CLI Usage

The `gptl` binary is the primary way to configure GPTL. Configuration is stored at
`~/.config/gptl/config.toml` (Unix) or `%APPDATA%\gptl\config.toml` (Windows).

### Commands

```
gptl status                              # Overview: level badge + all 11 protections
gptl config show                         # Full configuration table
gptl config show --format json           # Machine-readable JSON
gptl config set <key> <value>            # Change a setting (security changes require confirmation)
gptl config keys                         # All settable keys with accepted values
gptl config reset                        # Reset to defaults
gptl config path                         # Show config file location

gptl security level standard|enhanced|maximum   # Change security level (shows full diff + confirms)
gptl security level enhanced --label-only        # Update label only, keep individual settings
gptl security status                             # Protection checklist
gptl security audit                              # Detect mismatches and weaknesses

gptl profile list                        # List profiles (built-ins: standard/enhanced/maximum)
gptl profile show <name>                 # Preview a profile
gptl profile apply <name>                # Apply profile (shows diff + confirmation)
gptl profile save <name>                 # Save current config as named profile
gptl profile delete <name>               # Delete a saved profile

# Skip confirmation prompts (for scripting):
gptl -y security level maximum
gptl --yes profile apply standard
```

Security-sensitive changes (disabling protections, lowering security level) always show
a diff of what will change and ask for confirmation. Use `-y`/`--yes` to bypass in scripts.

## Security Levels

GPTL provides three configurable security levels:

### Standard
- Basic traffic padding
- DNS-over-HTTPS protection
- WebRTC leak prevention
- Suitable for: General browsing

### Enhanced (Default)
- All Standard features
- Timing protection with jitter
- Circuit obfuscation
- Vanguard layered guards
- Defends against: Traffic analysis, circuit fingerprinting

### Maximum
- All Enhanced features
- BGP-aware routing
- Multi-path traffic splitting
- Aggressive padding and obfuscation
- Suitable for: High-risk situations, activists, journalists

## Module Structure

### `gptl-core`
Core anti-surveillance protections:

- **`anti_surveillance/traffic_shaping.rs`** - Traffic confirmation attack defense
- **`anti_surveillance/padding.rs`** - Website fingerprinting defense (WTF-PAD)
- **`anti_surveillance/timing_protection.rs`** - Timing attack defense
- **`anti_surveillance/circuit_obfuscation.rs`** - Circuit fingerprinting defense
- **`anti_surveillance/flow_correlation_defense.rs`** - DeepCorr defense

### `gptl-routing`
Secure routing and network-level protections:

- **`bgp_protection.rs`** - RAPTOR/BGP hijacking defense with RPKI validation
- **`guard_management.rs`** - Vanguard protection against guard discovery
- **`resource_protection.rs`** - Sniper attack defense with PoW
- **`dns_protection.rs`** - DNS leak prevention with DoH/DoT
- **`webrtc_protection.rs`** - WebRTC leak prevention
- **`sybil_defense.rs`** - Sybil attack detection and prevention
- **`circuit/`** - Circuit pool, health monitoring, and rotation

### `gptl-crypto`
Production-grade cryptographic primitives (FIPS 140-3 validated via aws-lc-rs):

- **AEAD ciphers** — AES-256-GCM (primary), ChaCha20-Poly1305 (fallback)
- **Key exchange** — X25519 and Hybrid X25519 + ML-KEM-768 (post-quantum, NIST FIPS 203)
- **Forward secrecy** — Per-message symmetric key ratchet (Double-Ratchet-inspired) with an optional sending-side DH ratchet step; not a full bidirectional Double Ratchet
- **Counter-based nonces** — NIST-compliant with automatic rotation at 2³² messages
- **Memory safety** — All keys and secrets zeroized on drop

### `gptl-cli`
User-facing command-line interface (`gptl` binary):

- **`main.rs`** — Entry point; dispatches `config`, `security`, `profile`, and `status` subcommands
- Config stored at `~/.config/gptl/config.toml` (Unix) / `%APPDATA%\gptl\config.toml` (Windows)
- Built-in profiles: `standard`, `enhanced`, `maximum` (read-only)
- User profiles: `~/.config/gptl/profiles/<name>.toml`
- Security-sensitive changes require confirmation; use `-y`/`--yes` for scripting

### `gptl-transport`
Wire-level transport layer:

- **Cell protocol** — Fixed 512-byte cells resist traffic-size analysis
- **ntor-lite handshake** — X25519 + HKDF-SHA256 key agreement with HMAC key confirmation
- **Per-circuit encryption** — ChaCha20-Poly1305 with per-direction counter nonces (replay-resistant on the in-order stream; the receive counter only advances after a cell authenticates)
- **Multi-hop circuits** — Two-hop layered encryption via circuit extension
- **SOCKS5 proxy** — RFC 1928 client interface with IPv4, IPv6, and domain support
- **Guard persistence** — Persistent entry guards with rotation and failure tracking
- **Circuit pool** — Pre-built circuits with age/stream expiration and background refill
- **Exit policy** — Blocks connections to private/localhost addresses and SMTP ports
- **Resource limits** — Per-relay caps on concurrent circuits, streams per circuit, and circuit lifetime
- **Padding injection** — Random-interval padding cells during data transfer for traffic analysis resistance
- **Constant-time comparison** — All cryptographic comparisons use the `subtle` crate

### `gptl-relay`
Enterprise relay server with multi-layer security:

- **`auth/`** — Multi-factor authentication (password, TOTP, WebAuthn, mTLS)
- **`ip_restriction/`** — IP allowlist, geolocation blocking, threat intelligence
- **`rate_limit/`** — Token bucket limiting with CAPTCHA integration
- **`session/`** — JWT-based session management with binding
- **`api_key/`** — Scoped API key management with HMAC validation
- **`audit/`** — Tamper-evident audit log with Merkle tree integrity
- **`auto_setup.rs`** — Cross-platform firewall automation (UFW/iptables/nftables, netsh, pfctl)

## Research Documentation

See [`research/TOR_I2P_VPN_ATTACKS_RESEARCH_REPORT.md`](research/TOR_I2P_VPN_ATTACKS_RESEARCH_REPORT.md) for comprehensive analysis of each attack category including:

- Attack mechanisms and effectiveness
- Historical context and evolution
- Academic references
- GPTL countermeasure design rationale

## Key Features

### 1. Traffic Confirmation Defense
- Constant-rate cell transmission
- Multi-path routing
- Cover traffic generation
- Congestion-independent timing

### 2. Website Fingerprinting Defense
- WTF-PAD adaptive padding
- Burst morphing
- Standardized traffic patterns
- Game-theoretic optimization

### 3. Circuit Fingerprinting Defense
- Preemptive circuit padding (PCP)
- Vanguard layered guards
- Circuit type obfuscation
- Standardized cell sequences with random payloads (indistinguishable from real data)

### 4. Guard Discovery Defense
- 3-layer guard architecture
- Predecessor attack detection
- DoS-resistant rotation
- Reputation-based selection

### 5. Sniper Attack Defense
- Proof-of-work circuit allocation
- Memory pool management
- Window-based flow control
- Circuit prioritization

### 6. Sybil Defense
- Economic stake requirements
- Reputation system
- Behavioral pattern detection
- Bandwidth verification
- Trust networks

### 7. BGP Hijacking Defense
- RPKI route validation
- AS-aware path selection (intermediate-hop diversity)
- Real-time hijack detection
- Counter-RAPTOR selection

### 8. Timing Attack Defense
- Poisson-distributed jitter
- Packet batching and reordering
- Clock skew protection
- Watermark detection

### 9. DNS Leak Prevention
- DNS-over-HTTPS (DoH)
- DNS-over-TLS (DoT)
- Transparent proxy detection
- System DNS management

### 10. WebRTC Leak Prevention
- ICE candidate filtering
- TURN relay enforcement
- Browser policy enforcement
- Leak testing

## Cryptography

GPTL uses production-grade cryptographic primitives:

| Primitive | Algorithm | Standard |
|-----------|-----------|----------|
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 |
| Symmetric fallback | ChaCha20-Poly1305 | RFC 8439 |
| Classic key exchange | X25519 | RFC 7748 |
| Post-quantum KEM | ML-KEM-768 (Kyber) | NIST FIPS 203 |
| Hybrid key exchange | X25519 + ML-KEM-768 | IETF draft-ietf-tls-ecdhe-mlkem |
| Forward secrecy | Symmetric KDF ratchet (Double-Ratchet-inspired) | HKDF-SHA256 |
| Crypto library | aws-lc-rs | FIPS 140-3 validated |

Key properties:
- All keys and secrets are memory-zeroized on drop (`zeroize` crate)
- Constant-time operations for sensitive comparisons (`subtle` crate)
- Counter-based nonces with automatic rotation at 2³² messages
- Hybrid KEM provides both classical and post-quantum security

## Configuration

```rust
use gptl_core::anti_surveillance::{AntiSurveillanceManager, SecurityLevel};
use gptl_routing::RoutingManager;

#[tokio::main]
async fn main() {
    // Configure security level
    let mut manager = AntiSurveillanceManager::new(Default::default());
    manager.set_security_level(SecurityLevel::Maximum).await;

    // Initialize protections
    manager.initialize().await.unwrap();

    // Process cells securely
    let protected_cells = manager.protect_outgoing(cell).await.unwrap();
}
```

## Testing

Each module includes comprehensive unit tests:

```bash
# Run all tests
cd rust && cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run specific module tests
cargo test -p gptl-crypto
cargo test -p gptl-core
cargo test timing_protection
cargo test sybil_defense
```

## Security Considerations

### Current Limitations
- Requires integration with a transport layer for full deployment
- Network-level consensus and directory authority system not included
- Performance optimizations for high-throughput scenarios are ongoing
- **No network-wide congestion control yet** (no RTT/window flow control à la Tor
  proposal 324), so throughput/congestion confirmation is not specifically mitigated
- **AS-aware path selection is partial**: Counter-RAPTOR-style resilience scoring exists,
  but live AS-path lookup is not yet wired to real BGP/RouteViews data
- **The wire transport handshake is classical X25519 (ntor-style two-DH).** A hybrid
  X25519 + ML-KEM-768 KEM is implemented in `gptl-crypto` but is not yet wired into the
  circuit handshake, so harvest-now-decrypt-later resistance is not yet end-to-end
- **No probe-resistant bridge transport** (no obfs4/ScrambleSuit-style authenticated,
  high-entropy obfuscation), so entry points are not designed to survive an active
  prober or a censor's passive fully-encrypted-traffic heuristics

### Threat model and modern-attack resistance (2025)

Low-latency anonymity cannot defeat a **global / end-to-end passive adversary**: an
attacker who observes both the entry and exit sides can correlate flows by timing and
volume. Modern deep-learning flow-correlation attacks — **DeepCorr** (Nasr et al., CCS
2018) and **DeepCoFFEA** (Oh et al., IEEE S&P 2022) — make this practical, and no
low-overhead padding defeats it. GPTL therefore aims to *reduce the probability that one
adversary observes both ends* (entry guards, multi-layer vanguards, path/AS diversity,
traffic splitting), **not** to defeat correlation itself.

| Modern attack | GPTL posture | Status |
|---|---|---|
| Tagging attacks on relay crypto | Per-cell AEAD (ChaCha20-Poly1305, 16-byte tag) — any tampering fails authentication; no malleable AES-CTR + short MAC | **Resisted** |
| Guard discovery (Øverlier–Syverson; PoPETs 2022) | 3-layer guard system (vanguards) with layered rotation | **Mitigated** |
| Sniper / resource-exhaustion DoS (NDSS 2014) | Proof-of-work circuit allocation, bounded queues, per-circuit caps, per-IP connection cap, handshake timeout | **Mitigated** |
| Onion-service flooding DoS (2019–2020) | Proof-of-work with effort-scaled difficulty | **Mitigated** |
| Circuit fingerprinting (Kwon et al., USENIX 2015) | Preemptive circuit padding + cell-sequence normalization | **Partial** |
| Website fingerprinting — DL attacks (DF, CCS 2018; Tik-Tok, PoPETs 2020) | WTF-PAD-style adaptive padding **plus** traffic splitting across paths. Note: WTF-PAD alone is broken by DF/Tik-Tok; splitting (TrafficSliver, CCS 2020) and regularization (RegulaTor, PoPETs 2022) are the credible directions | **Partial — padding alone is not sufficient** |
| Flow correlation (DeepCorr; DeepCoFFEA) | Reduce both-ends observation via guards/diversity/splitting | **Fundamental limit — not defeated** |
| RAPTOR / BGP & AS-level adversary (USENIX 2015) | RPKI ROV (RFC 6811), Counter-RAPTOR-style resilient selection, AS-path diversity | **Partial (no live AS data yet)** |
| Active probing / fully-encrypted-traffic detection (USENIX 2023) | Relay is silent to non-protocol input and closes promptly; no banner to fingerprint | **Partial (no obfuscated bridge transport)** |
| Harvest-now-decrypt-later (quantum) | Hybrid X25519 + ML-KEM-768 available in `gptl-crypto` | **Not yet wired into the transport handshake** |

References for each attack are collected in
[`research/TOR_I2P_VPN_ATTACKS_RESEARCH_REPORT.md`](research/TOR_I2P_VPN_ATTACKS_RESEARCH_REPORT.md).

### Security Properties
- **Memory safety**: Rust ownership model eliminates use-after-free and buffer overflows
- **Cryptographic agility**: Hybrid classical + post-quantum key exchange available in `gptl-crypto`
- **Forward secrecy**: Per-message symmetric key ratchet (Double-Ratchet-inspired); session keys are ephemeral per circuit
- **Bounded resource usage**: All data structures have growth limits to prevent DoS
- **Tamper-evident logging**: Merkle tree-backed audit log with cryptographic integrity
- **Relay exit policy**: Private addresses (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, etc.) and SMTP ports blocked
- **Relay resource limits**: Concurrent circuit cap, per-circuit stream cap, handshake timeout, circuit lifetime limit
- **Traffic padding**: Random-interval padding cells injected during active connections
- **Key material hygiene**: Session keys are non-cloneable and zeroized on drop

## Contributing

This project is part of the GPTL security research initiative. See individual module documentation for contribution guidelines.

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Acknowledgments

This implementation is based on research by:

- Murdoch & Danezis (2005) - Traffic confirmation attacks
- Panchenko et al. (2011, 2016) - Website fingerprinting
- Kwon et al. (2015) - Circuit fingerprinting attacks
- Overlier & Syverson (2006) - Guard discovery
- Jansen et al. (2014) - Sniper attacks
- Sun et al. (2015) - RAPTOR attacks
- Biryukov et al. (2013) - Sybil attacks

---

*Note: This is a security research implementation. Production deployment requires additional operational hardening and network infrastructure.*
