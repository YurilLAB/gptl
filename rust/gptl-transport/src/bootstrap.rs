//! Relay directory bootstrap.
//!
//! For Phase 1, the directory is a simple JSON/TOML file listing relay endpoints.
//! The client loads this file at startup and picks a relay using the configured
//! selection strategy.
//!
//! Future phases will replace this with a signed, consensus-based directory.

use crate::TransportError;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;

/// A relay descriptor — one entry in the bootstrap directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelayDescriptor {
    /// Human-readable nickname (optional, for logs/UI)
    pub nickname: String,
    /// TCP address the relay listens on for transport connections
    pub address: String,
    /// Relay's static X25519 public key, hex-encoded (64 hex chars = 32 bytes)
    pub pubkey_hex: String,
}

impl RelayDescriptor {
    /// Parse the hex pubkey into 32 bytes.
    pub fn pubkey_bytes(&self) -> Result<[u8; 32], TransportError> {
        let bytes = hex::decode(&self.pubkey_hex).map_err(|e| {
            TransportError::Bootstrap(format!("invalid pubkey hex in '{}': {}", self.nickname, e))
        })?;
        bytes.try_into().map_err(|_| {
            TransportError::Bootstrap(format!(
                "pubkey for '{}' must be 32 bytes (64 hex chars)",
                self.nickname
            ))
        })
    }

    /// Parse and resolve the socket address.
    pub fn socket_addr(&self) -> Result<SocketAddr, TransportError> {
        self.address.parse::<SocketAddr>().map_err(|e| {
            TransportError::Bootstrap(format!("invalid address '{}': {}", self.address, e))
        })
    }
}

/// Bootstrap directory: the list of known relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// All known relay descriptors
    pub relays: Vec<RelayDescriptor>,
}

impl BootstrapConfig {
    /// Load from a JSON file.
    pub fn from_json_file(path: &Path) -> Result<Self, TransportError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| TransportError::Bootstrap(format!("read {}: {}", path.display(), e)))?;
        serde_json::from_str(&contents)
            .map_err(|e| TransportError::Bootstrap(format!("parse {}: {}", path.display(), e)))
    }

    /// Load from inline JSON string (for testing or embedded configs).
    pub fn from_json_str(json: &str) -> Result<Self, TransportError> {
        serde_json::from_str(json)
            .map_err(|e| TransportError::Bootstrap(format!("parse JSON: {}", e)))
    }

    /// Pick a relay at random (uniform distribution).
    pub fn pick_random(&self) -> Option<&RelayDescriptor> {
        if self.relays.is_empty() {
            return None;
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..self.relays.len());
        Some(&self.relays[idx])
    }

    /// Find a relay by nickname.
    pub fn find_by_nickname(&self, name: &str) -> Option<&RelayDescriptor> {
        self.relays.iter().find(|r| r.nickname == name)
    }

    /// Pick a random relay whose nickname is not `excluded`.
    ///
    /// Used when building multi-hop circuits to ensure relay1 ≠ relay2.
    pub fn pick_relay_excluding(&self, excluded: &str) -> Option<&RelayDescriptor> {
        let candidates: Vec<&RelayDescriptor> = self
            .relays
            .iter()
            .filter(|r| r.nickname != excluded)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..candidates.len());
        Some(candidates[idx])
    }

    /// Validate all descriptors (parseable addresses, well-formed pubkeys, no duplicates).
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.relays.is_empty() {
            return Err(TransportError::Bootstrap(
                "directory is empty — add at least one relay".into(),
            ));
        }

        let mut seen_nicknames = std::collections::HashSet::new();
        let mut seen_pubkeys = std::collections::HashSet::new();

        for r in &self.relays {
            r.pubkey_bytes()?;
            r.socket_addr()?;

            if !seen_nicknames.insert(r.nickname.as_str()) {
                return Err(TransportError::Bootstrap(format!(
                    "duplicate relay nickname '{}'",
                    r.nickname
                )));
            }
            if !seen_pubkeys.insert(r.pubkey_hex.as_str()) {
                return Err(TransportError::Bootstrap(format!(
                    "duplicate relay pubkey in entry '{}'",
                    r.nickname
                )));
            }
        }
        Ok(())
    }
}

/// Default bootstrap config path.
pub fn default_bootstrap_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("gptl").join("relays.json"))
}

/// Write a bootstrap config to a JSON file (used by `gptl-node` to publish itself).
pub fn save_bootstrap(config: &BootstrapConfig, path: &Path) -> Result<(), TransportError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| TransportError::Bootstrap(format!("create dir: {}", e)))?;
    }
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| TransportError::Bootstrap(format!("serialize: {}", e)))?;
    std::fs::write(path, json)
        .map_err(|e| TransportError::Bootstrap(format!("write {}: {}", path.display(), e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::RelayStaticKey;

    fn make_descriptor(key: &RelayStaticKey) -> RelayDescriptor {
        RelayDescriptor {
            nickname: "test-relay".into(),
            address: "127.0.0.1:9001".into(),
            pubkey_hex: hex::encode(key.public),
        }
    }

    #[test]
    fn test_descriptor_pubkey_roundtrip() {
        let key = RelayStaticKey::generate();
        let desc = make_descriptor(&key);
        let bytes = desc.pubkey_bytes().unwrap();
        assert_eq!(bytes, key.public);
    }

    #[test]
    fn test_descriptor_socket_addr_parses() {
        let key = RelayStaticKey::generate();
        let desc = make_descriptor(&key);
        let addr = desc.socket_addr().unwrap();
        assert_eq!(addr.port(), 9001);
    }

    #[test]
    fn test_invalid_pubkey_hex_rejected() {
        let desc = RelayDescriptor {
            nickname: "bad".into(),
            address: "127.0.0.1:9001".into(),
            pubkey_hex: "not-valid-hex!!!".into(),
        };
        assert!(desc.pubkey_bytes().is_err());
    }

    #[test]
    fn test_short_pubkey_rejected() {
        let desc = RelayDescriptor {
            nickname: "short".into(),
            address: "127.0.0.1:9001".into(),
            pubkey_hex: "aabbcc".into(), // only 3 bytes
        };
        assert!(desc.pubkey_bytes().is_err());
    }

    #[test]
    fn test_invalid_address_rejected() {
        let key = RelayStaticKey::generate();
        let desc = RelayDescriptor {
            nickname: "bad-addr".into(),
            address: "not_an_address".into(),
            pubkey_hex: hex::encode(key.public),
        };
        assert!(desc.socket_addr().is_err());
    }

    #[test]
    fn test_bootstrap_json_roundtrip() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![make_descriptor(&key)],
        };
        let json = serde_json::to_string(&config).unwrap();
        let loaded = BootstrapConfig::from_json_str(&json).unwrap();
        assert_eq!(loaded.relays.len(), 1);
        assert_eq!(loaded.relays[0].pubkey_hex, config.relays[0].pubkey_hex);
    }

    #[test]
    fn test_empty_directory_validation_fails() {
        let config = BootstrapConfig { relays: vec![] };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_valid_directory_passes_validation() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![make_descriptor(&key)],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pick_random_single_relay() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![make_descriptor(&key)],
        };
        let picked = config.pick_random();
        assert!(picked.is_some());
    }

    #[test]
    fn test_pick_random_empty_returns_none() {
        let config = BootstrapConfig { relays: vec![] };
        assert!(config.pick_random().is_none());
    }

    #[test]
    fn test_find_by_nickname() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![make_descriptor(&key)],
        };
        assert!(config.find_by_nickname("test-relay").is_some());
        assert!(config.find_by_nickname("nonexistent").is_none());
    }

    #[test]
    fn test_duplicate_nickname_rejected() {
        let key1 = RelayStaticKey::generate();
        let key2 = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![
                RelayDescriptor {
                    nickname: "same-name".into(),
                    address: "127.0.0.1:9001".into(),
                    pubkey_hex: hex::encode(key1.public),
                },
                RelayDescriptor {
                    nickname: "same-name".into(), // duplicate
                    address: "127.0.0.1:9002".into(),
                    pubkey_hex: hex::encode(key2.public),
                },
            ],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duplicate_pubkey_rejected() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![
                RelayDescriptor {
                    nickname: "relay-a".into(),
                    address: "127.0.0.1:9001".into(),
                    pubkey_hex: hex::encode(key.public),
                },
                RelayDescriptor {
                    nickname: "relay-b".into(),
                    address: "127.0.0.1:9002".into(),
                    pubkey_hex: hex::encode(key.public), // duplicate pubkey
                },
            ],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_unique_relays_pass_validation() {
        let key1 = RelayStaticKey::generate();
        let key2 = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![
                RelayDescriptor {
                    nickname: "relay-a".into(),
                    address: "127.0.0.1:9001".into(),
                    pubkey_hex: hex::encode(key1.public),
                },
                RelayDescriptor {
                    nickname: "relay-b".into(),
                    address: "127.0.0.1:9002".into(),
                    pubkey_hex: hex::encode(key2.public),
                },
            ],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_bootstrap_file_roundtrip() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![make_descriptor(&key)],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relays.json");
        save_bootstrap(&config, &path).unwrap();
        let loaded = BootstrapConfig::from_json_file(&path).unwrap();
        assert_eq!(loaded.relays[0].pubkey_hex, config.relays[0].pubkey_hex);
    }

    #[test]
    fn test_pick_relay_excluding_returns_different_relay() {
        let key1 = RelayStaticKey::generate();
        let key2 = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![
                RelayDescriptor {
                    nickname: "relay-a".into(),
                    address: "127.0.0.1:9001".into(),
                    pubkey_hex: hex::encode(key1.public),
                },
                RelayDescriptor {
                    nickname: "relay-b".into(),
                    address: "127.0.0.1:9002".into(),
                    pubkey_hex: hex::encode(key2.public),
                },
            ],
        };
        for _ in 0..20 {
            let picked = config.pick_relay_excluding("relay-a").unwrap();
            assert_eq!(picked.nickname, "relay-b");
        }
    }

    #[test]
    fn test_pick_relay_excluding_all_returns_none() {
        let key = RelayStaticKey::generate();
        let config = BootstrapConfig {
            relays: vec![RelayDescriptor {
                nickname: "only-one".into(),
                address: "127.0.0.1:9001".into(),
                pubkey_hex: hex::encode(key.public),
            }],
        };
        assert!(config.pick_relay_excluding("only-one").is_none());
    }

    #[test]
    fn test_from_json_str_invalid_json_returns_error() {
        let result = BootstrapConfig::from_json_str("not json");
        assert!(result.is_err());
    }
}
