//! Circuit path / relay selection.
//!
//! Selects an ordered sequence of relays for a circuit, applying
//! anonymity-preserving constraints (subnet diversity, nickname-prefix
//! uniqueness).

use crate::{bootstrap::RelayDescriptor, TransportError};
use rand::seq::SliceRandom;
use tracing::debug;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tuning parameters for path selection.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Desired number of hops.  Currently 1 or 2 are well-tested; 3 is
    /// architecturally supported but not yet deployed.
    pub num_hops: usize,
    /// Prevent two relays from sharing the same /24 subnet.
    pub exclude_same_subnet: bool,
    /// Prevent two relays whose nicknames share the same 8-character prefix.
    pub exclude_same_nickname_prefix: bool,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            num_hops: 2,
            exclude_same_subnet: true,
            exclude_same_nickname_prefix: true,
        }
    }
}

// ── RelayPath ─────────────────────────────────────────────────────────────────

/// An ordered sequence of relays forming a circuit path (entry → exit).
#[derive(Debug, Clone)]
pub struct RelayPath {
    /// Ordered relay descriptors.  `hops[0]` is the entry guard,
    /// `hops[last]` is the exit relay.
    pub hops: Vec<RelayDescriptor>,
}

impl RelayPath {
    /// The entry (first) relay.
    pub fn entry(&self) -> &RelayDescriptor {
        &self.hops[0]
    }

    /// The exit (last) relay.
    pub fn exit(&self) -> &RelayDescriptor {
        &self.hops[self.hops.len() - 1]
    }

    /// Number of hops in the path.
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// `true` if the path contains no hops.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

// ── PathSelector ─────────────────────────────────────────────────────────────

/// Selects relay paths subject to the configured diversity constraints.
pub struct PathSelector {
    config: PathConfig,
}

impl PathSelector {
    /// Create a new `PathSelector` with the given configuration.
    pub fn new(config: PathConfig) -> Self {
        Self { config }
    }

    /// Select a relay path from `available`.
    ///
    /// If `guard` is `Some`, it is used as the first hop unconditionally.
    /// Returns `Err` if there are not enough relays to form even a 1-hop path.
    pub fn select_path(
        &self,
        available: &[RelayDescriptor],
        guard: Option<&RelayDescriptor>,
    ) -> Result<RelayPath, TransportError> {
        if available.is_empty() && guard.is_none() {
            return Err(TransportError::Bootstrap("insufficient relays for path selection".into()));
        }

        let target_hops = self.config.num_hops.max(1);
        let mut hops: Vec<RelayDescriptor> = Vec::with_capacity(target_hops);

        // ── Hop 0: guard or random pick ───────────────────────────────────────
        if let Some(g) = guard {
            hops.push(g.clone());
        } else {
            // Pick randomly from available.
            let pick = available
                .choose(&mut rand::thread_rng())
                .ok_or_else(|| TransportError::Bootstrap("insufficient relays for path selection".into()))?;
            hops.push(pick.clone());
        }

        // ── Subsequent hops ───────────────────────────────────────────────────
        for _ in 1..target_hops {
            // Build the candidate pool: available relays not already in the path
            // and passing diversity constraints.
            let candidates: Vec<&RelayDescriptor> = available
                .iter()
                .filter(|r| {
                    // Must not already be in the path.
                    if hops.iter().any(|h| h.pubkey_hex == r.pubkey_hex) {
                        return false;
                    }
                    // Subnet diversity.
                    if self.config.exclude_same_subnet {
                        if let Some(subnet) = parse_subnet_24(&r.address) {
                            for h in &hops {
                                if parse_subnet_24(&h.address) == Some(subnet) {
                                    return false;
                                }
                            }
                        }
                    }
                    // Nickname-prefix diversity.
                    if self.config.exclude_same_nickname_prefix {
                        let prefix: &str = r.nickname.get(..8.min(r.nickname.len())).unwrap_or(&r.nickname);
                        if !prefix.is_empty() {
                            for h in &hops {
                                let hp: &str = h.nickname.get(..8.min(h.nickname.len())).unwrap_or(&h.nickname);
                                if hp == prefix {
                                    return false;
                                }
                            }
                        }
                    }
                    true
                })
                .collect();

            if candidates.is_empty() {
                // Not enough diversity — stop here (path is shorter than desired).
                debug!(
                    "path length capped at {} hops due to insufficient diverse relays",
                    hops.len()
                );
                break;
            }

            let pick = candidates
                .choose(&mut rand::thread_rng())
                .expect("candidates is non-empty; qed");
            hops.push((*pick).clone());
        }

        if hops.is_empty() {
            return Err(TransportError::Bootstrap("insufficient relays for path selection".into()));
        }

        debug!("selected {}-hop path: {:?}", hops.len(), hops.iter().map(|h| &h.nickname).collect::<Vec<_>>());
        Ok(RelayPath { hops })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse the first three octets (the /24 subnet) from an `"ip:port"` string.
///
/// Returns `None` for IPv6 addresses, non-IPv4 strings, or parse failures.
pub fn parse_subnet_24(addr: &str) -> Option<[u8; 3]> {
    // Strip the port suffix if present.
    let host = if let Some(bracket_end) = addr.strip_prefix('[') {
        // IPv6 bracket notation — not supported.
        let _ = bracket_end;
        return None;
    } else {
        // "ip:port" — split on the last ':'.
        match addr.rsplit_once(':') {
            Some((host, _port)) => host,
            None => addr,
        }
    };

    let octets: Vec<u8> = host
        .split('.')
        .filter_map(|o| o.parse::<u8>().ok())
        .collect();

    if octets.len() == 4 {
        Some([octets[0], octets[1], octets[2]])
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_relay(nickname: &str, ip: &str, pubkey_suffix: u8) -> RelayDescriptor {
        RelayDescriptor {
            nickname: nickname.to_string(),
            address: format!("{}:9001", ip),
            pubkey_hex: format!("{:0>63x}{:x}", 0u8, pubkey_suffix),
        }
    }

    fn diverse_relays() -> Vec<RelayDescriptor> {
        vec![
            make_relay("alpha",   "10.0.1.1", 1),
            make_relay("bravo",   "10.0.2.1", 2),
            make_relay("charlie", "10.0.3.1", 3),
            make_relay("delta",   "10.0.4.1", 4),
            make_relay("echo",    "10.0.5.1", 5),
        ]
    }

    // ── parse_subnet_24 ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_subnet_24_valid() {
        assert_eq!(parse_subnet_24("10.0.1.5:9001"), Some([10, 0, 1]));
        assert_eq!(parse_subnet_24("192.168.0.1:1234"), Some([192, 168, 0]));
    }

    #[test]
    fn test_parse_subnet_24_ipv6_returns_none() {
        assert_eq!(parse_subnet_24("[::1]:9001"), None);
    }

    #[test]
    fn test_parse_subnet_24_no_port() {
        // Raw IP without port — still parses.
        assert_eq!(parse_subnet_24("1.2.3.4"), Some([1, 2, 3]));
    }

    // ── select_path ───────────────────────────────────────────────────────────

    #[test]
    fn test_single_hop_path() {
        let relays = diverse_relays();
        let config = PathConfig { num_hops: 1, ..Default::default() };
        let selector = PathSelector::new(config);
        let path = selector.select_path(&relays, None).unwrap();
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_two_hop_path_different_relays() {
        let relays = diverse_relays();
        let config = PathConfig { num_hops: 2, ..Default::default() };
        let selector = PathSelector::new(config);
        let path = selector.select_path(&relays, None).unwrap();
        assert_eq!(path.len(), 2);
        assert_ne!(path.entry().pubkey_hex, path.exit().pubkey_hex);
    }

    #[test]
    fn test_guard_pinned_as_entry() {
        let relays = diverse_relays();
        let guard = &relays[2]; // charlie
        let config = PathConfig { num_hops: 2, ..Default::default() };
        let selector = PathSelector::new(config);
        let path = selector.select_path(&relays, Some(guard)).unwrap();
        assert_eq!(path.entry().nickname, "charlie");
    }

    #[test]
    fn test_subnet_exclusion_enforced() {
        // Two relays on the same /24; a third on a different subnet.
        let relays = vec![
            make_relay("same1", "192.168.1.10", 10),
            make_relay("same2", "192.168.1.20", 20),
            make_relay("other", "10.0.0.1",     30),
        ];
        let config = PathConfig {
            num_hops: 2,
            exclude_same_subnet: true,
            exclude_same_nickname_prefix: false,
        };
        let selector = PathSelector::new(config);
        // Run many times to rule out lucky random picks.
        for _ in 0..30 {
            let path = selector.select_path(&relays, None).unwrap();
            if path.len() == 2 {
                assert_ne!(
                    parse_subnet_24(&path.entry().address),
                    parse_subnet_24(&path.exit().address),
                    "subnet exclusion violated"
                );
            }
        }
    }

    #[test]
    fn test_insufficient_relays_returns_error() {
        let config = PathConfig { num_hops: 1, ..Default::default() };
        let selector = PathSelector::new(config);
        let result = selector.select_path(&[], None);
        assert!(result.is_err(), "should fail with 0 available relays and no guard");
    }

    #[test]
    fn test_path_with_only_one_relay_caps_at_one_hop() {
        let relays = vec![make_relay("solo", "10.0.0.1", 1)];
        let config = PathConfig { num_hops: 2, ..Default::default() };
        let selector = PathSelector::new(config);
        let path = selector.select_path(&relays, None).unwrap();
        // Can only build 1 hop.
        assert_eq!(path.len(), 1);
    }

    #[test]
    fn test_path_entry_exit_accessors() {
        let relays = diverse_relays();
        let config = PathConfig { num_hops: 2, ..Default::default() };
        let selector = PathSelector::new(config);
        let path = selector.select_path(&relays, None).unwrap();
        // entry() and exit() must always resolve to valid descriptors.
        let _ = path.entry();
        let _ = path.exit();
    }

    // ── no duplicate relays ───────────────────────────────────────────────────

    /// Run path selection many times and verify no relay appears twice in a path.
    #[test]
    fn test_no_duplicate_relays_in_path() {
        let relays = diverse_relays(); // 5 relays on distinct subnets
        let config = PathConfig { num_hops: 2, ..Default::default() };
        let selector = PathSelector::new(config);
        for _ in 0..50 {
            let path = selector.select_path(&relays, None).unwrap();
            let pubkeys: Vec<&str> = path.hops.iter().map(|r| r.pubkey_hex.as_str()).collect();
            let unique: std::collections::HashSet<&str> = pubkeys.iter().cloned().collect();
            assert_eq!(
                pubkeys.len(),
                unique.len(),
                "relay appeared more than once in path: {:?}",
                path.hops.iter().map(|r| &r.nickname).collect::<Vec<_>>()
            );
        }
    }

    // ── nickname prefix exclusion ─────────────────────────────────────────────

    /// Two relays whose nicknames share the same 8-char prefix must never both
    /// appear in a 2-hop path when `exclude_same_nickname_prefix` is enabled.
    #[test]
    fn test_nickname_prefix_exclusion_enforced() {
        // "guardxxx" and "guardyyy" share the 8-char prefix "guardxxx"/"guardyyy" (length 8)
        // Actually the prefix check is first 8 chars: "guardxxx" vs "guardyyy" — different.
        // Let's use exactly the same 8-char prefix: "relay001a" vs "relay001b" → prefix = "relay001"
        let relays = vec![
            make_relay("relay001a", "10.0.1.1", 1),  // prefix "relay001"
            make_relay("relay001b", "10.0.2.1", 2),  // prefix "relay001" (same!)
            make_relay("relay002a", "10.0.3.1", 3),  // prefix "relay002"
            make_relay("relay003a", "10.0.4.1", 4),  // prefix "relay003"
        ];
        let config = PathConfig {
            num_hops: 2,
            exclude_same_subnet: false,
            exclude_same_nickname_prefix: true,
        };
        let selector = PathSelector::new(config);

        for _ in 0..60 {
            let path = selector.select_path(&relays, None).unwrap();
            if path.len() < 2 {
                continue;
            }
            let entry_prefix: String = path.entry().nickname.chars().take(8).collect();
            let exit_prefix: String = path.exit().nickname.chars().take(8).collect();
            assert_ne!(
                entry_prefix, exit_prefix,
                "two relays with the same nickname prefix appeared in the same path: {} and {}",
                path.entry().nickname,
                path.exit().nickname,
            );
        }
    }
}
