//! Relay directory bootstrap.
//!
//! The directory is a JSON file listing relay endpoints. It may be loaded
//! either **unsigned** (trust-on-first-use / local testing) or as a
//! [`SignedDirectory`] verified against a pinned ed25519 authority key — the
//! latter authenticates the root of trust so a tampered directory cannot
//! substitute attacker-controlled relays.

use crate::TransportError;
use ed25519_dalek::Signer;
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

    /// Load a **signed** directory from a JSON file and verify it against a
    /// pinned ed25519 authority public key (hex, 64 chars). The relays are
    /// trusted only if the signature verifies AND the file's authority key
    /// matches the pinned one (so this is authentication, not trust-on-first-use).
    pub fn from_signed_json_file(path: &Path, authority_hex: &str) -> Result<Self, TransportError> {
        let expected = decode_authority_key(authority_hex)?;
        let contents = std::fs::read_to_string(path)
            .map_err(|e| TransportError::Bootstrap(format!("read {}: {}", path.display(), e)))?;
        let signed: SignedDirectory = serde_json::from_str(&contents).map_err(|e| {
            TransportError::Bootstrap(format!("parse signed directory {}: {}", path.display(), e))
        })?;
        signed.verify(&expected)
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

/// Domain-separation tag for directory signatures.
const DIRECTORY_SIG_DOMAIN: &[u8] = b"gptl-directory-v1\n";

/// Deterministic, unambiguous byte encoding of a relay list for signing.
///
/// Each field is length-prefixed so that no two distinct directories can ever
/// produce the same message (a plain concatenation would let
/// nickname="ab",address="c" collide with nickname="a",address="bc").
fn canonical_directory_bytes(relays: &[RelayDescriptor]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(DIRECTORY_SIG_DOMAIN.len() + relays.len() * 96);
    msg.extend_from_slice(DIRECTORY_SIG_DOMAIN);
    msg.extend_from_slice(&(relays.len() as u32).to_be_bytes());
    for r in relays {
        for field in [&r.nickname, &r.address, &r.pubkey_hex] {
            msg.extend_from_slice(&(field.len() as u32).to_be_bytes());
            msg.extend_from_slice(field.as_bytes());
        }
    }
    msg
}

/// Decode a 32-byte ed25519 authority public key from hex.
fn decode_authority_key(hex_str: &str) -> Result<[u8; 32], TransportError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| TransportError::Bootstrap(format!("invalid authority key hex: {}", e)))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Bootstrap("authority key must be 32 bytes (64 hex)".into()))
}

/// A relay directory plus an ed25519 authority signature over it.
///
/// The signature covers [`canonical_directory_bytes`] of `relays`, so any
/// modification (adding/removing/altering a relay) invalidates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDirectory {
    /// The signed relay descriptors.
    pub relays: Vec<RelayDescriptor>,
    /// ed25519 signature, hex-encoded (128 hex chars = 64 bytes).
    pub signature: String,
    /// ed25519 authority public key, hex-encoded (64 hex chars = 32 bytes).
    pub authority_key: String,
}

impl SignedDirectory {
    /// Sign a relay list with an ed25519 authority signing key.
    pub fn sign(relays: Vec<RelayDescriptor>, signing_key: &ed25519_dalek::SigningKey) -> Self {
        let msg = canonical_directory_bytes(&relays);
        let signature = signing_key.sign(&msg);
        SignedDirectory {
            relays,
            signature: hex::encode(signature.to_bytes()),
            authority_key: hex::encode(signing_key.verifying_key().to_bytes()),
        }
    }

    /// Verify against a PINNED authority public key and return the trusted
    /// [`BootstrapConfig`]. Fails if the embedded authority key differs from the
    /// pinned key, if the signature is invalid, or if the directory is malformed.
    pub fn verify(&self, expected_authority: &[u8; 32]) -> Result<BootstrapConfig, TransportError> {
        // The authority key in the file must match the pinned key — otherwise an
        // attacker could simply re-sign a forged directory with their own key.
        let auth = decode_authority_key(&self.authority_key)?;
        if auth != *expected_authority {
            return Err(TransportError::Bootstrap(
                "directory authority key does not match the pinned authority key".into(),
            ));
        }
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&auth)
            .map_err(|e| TransportError::Bootstrap(format!("invalid authority key: {}", e)))?;

        let sig_bytes = hex::decode(self.signature.trim())
            .map_err(|e| TransportError::Bootstrap(format!("invalid signature hex: {}", e)))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TransportError::Bootstrap("signature must be 64 bytes".into()))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let msg = canonical_directory_bytes(&self.relays);
        // verify_strict rejects non-canonical signatures / small-order keys.
        vk.verify_strict(&msg, &signature).map_err(|_| {
            TransportError::Bootstrap("directory signature verification failed".into())
        })?;

        let cfg = BootstrapConfig {
            relays: self.relays.clone(),
        };
        cfg.validate()?;
        Ok(cfg)
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

    // ── Signed directory ───────────────────────────────────────────────────────

    fn authority() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn two_relays() -> Vec<RelayDescriptor> {
        let k1 = RelayStaticKey::generate();
        let k2 = RelayStaticKey::generate();
        vec![
            RelayDescriptor {
                nickname: "relay-a".into(),
                address: "127.0.0.1:9001".into(),
                pubkey_hex: hex::encode(k1.public),
            },
            RelayDescriptor {
                nickname: "relay-b".into(),
                address: "127.0.0.1:9002".into(),
                pubkey_hex: hex::encode(k2.public),
            },
        ]
    }

    #[test]
    fn test_signed_directory_roundtrip() {
        let sk = authority();
        let pinned = sk.verifying_key().to_bytes();
        let signed = SignedDirectory::sign(two_relays(), &sk);
        let cfg = signed.verify(&pinned).expect("valid signature must verify");
        assert_eq!(cfg.relays.len(), 2);
    }

    #[test]
    fn test_signed_directory_tamper_rejected() {
        let sk = authority();
        let pinned = sk.verifying_key().to_bytes();
        let mut signed = SignedDirectory::sign(two_relays(), &sk);
        // Attacker swaps in their own relay address (keeping the signature).
        signed.relays[0].address = "127.0.0.1:6666".into();
        assert!(
            signed.verify(&pinned).is_err(),
            "a modified directory must fail signature verification"
        );

        // Attacker adds a relay.
        let mut signed2 = SignedDirectory::sign(two_relays(), &sk);
        signed2.relays.push(RelayDescriptor {
            nickname: "evil".into(),
            address: "10.0.0.1:9001".into(),
            pubkey_hex: hex::encode(RelayStaticKey::generate().public),
        });
        assert!(
            signed2.verify(&pinned).is_err(),
            "added relay must be rejected"
        );
    }

    #[test]
    fn test_signed_directory_wrong_authority_rejected() {
        let real = authority();
        let pinned = real.verifying_key().to_bytes();

        // Attacker re-signs a forged directory with THEIR own key.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let forged = SignedDirectory::sign(two_relays(), &attacker);
        assert!(
            forged.verify(&pinned).is_err(),
            "a directory signed by a non-pinned authority must be rejected"
        );
    }

    #[test]
    fn test_signed_directory_corrupt_signature_rejected() {
        let sk = authority();
        let pinned = sk.verifying_key().to_bytes();
        let mut signed = SignedDirectory::sign(two_relays(), &sk);
        // Flip a byte in the hex signature.
        let mut sig: Vec<u8> = signed.signature.into_bytes();
        sig[0] = if sig[0] == b'a' { b'b' } else { b'a' };
        signed.signature = String::from_utf8(sig).unwrap();
        assert!(signed.verify(&pinned).is_err());
    }

    #[test]
    fn test_from_signed_json_file_roundtrip_and_tamper() {
        let sk = authority();
        let authority_hex = hex::encode(sk.verifying_key().to_bytes());
        let signed = SignedDirectory::sign(two_relays(), &sk);
        let json = serde_json::to_string_pretty(&signed).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed-relays.json");
        std::fs::write(&path, &json).unwrap();

        // Valid load against the correct pinned key.
        let cfg = BootstrapConfig::from_signed_json_file(&path, &authority_hex).unwrap();
        assert_eq!(cfg.relays.len(), 2);

        // Loading against a different pinned key must fail.
        let other_hex = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(BootstrapConfig::from_signed_json_file(&path, &other_hex).is_err());

        // Tampering with the file on disk must fail verification.
        let tampered = json.replace("127.0.0.1:9001", "127.0.0.1:6666");
        std::fs::write(&path, tampered).unwrap();
        assert!(BootstrapConfig::from_signed_json_file(&path, &authority_hex).is_err());
    }
}
