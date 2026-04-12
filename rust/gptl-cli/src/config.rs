//! GPTL unified configuration management.
//!
//! Config is stored as TOML at `~/.config/gptl/config.toml` (Unix) or
//! `%APPDATA%\gptl\config.toml` (Windows). On first run the file is created
//! automatically with sensible defaults.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur when loading, saving, or mutating the config.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),
    #[error("TOML serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("Cannot determine config directory — set HOME or APPDATA")]
    NoDirFound,
    #[error("Unknown config key '{0}'. Run 'gptl config show' to see all valid keys.")]
    UnknownKey(String),
    #[error("Invalid value for '{key}': {message}")]
    InvalidValue { key: String, message: String },
}

// ── SecurityLevel ─────────────────────────────────────────────────────────────

/// Protection level preset, each with a recommended set of feature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    /// Minimal overhead: basic padding and DNS/WebRTC protection.
    Standard,
    /// Moderate overhead: adds timing shield, circuit obfuscation, vanguards.
    /// This is the default.
    Enhanced,
    /// Higher overhead: full obfuscation, BGP guard, multi-path routing.
    Maximum,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Enhanced
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityLevel::Standard => write!(f, "standard"),
            SecurityLevel::Enhanced => write!(f, "enhanced"),
            SecurityLevel::Maximum  => write!(f, "maximum"),
        }
    }
}

impl std::str::FromStr for SecurityLevel {
    type Err = ConfigError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" => Ok(SecurityLevel::Standard),
            "enhanced" => Ok(SecurityLevel::Enhanced),
            "maximum"  => Ok(SecurityLevel::Maximum),
            _ => Err(ConfigError::InvalidValue {
                key: "security_level".to_string(),
                message: format!("expected standard, enhanced, or maximum — got '{}'", s),
            }),
        }
    }
}

impl SecurityLevel {
    /// One-line description suitable for display next to the level badge.
    pub fn description(self) -> &'static str {
        match self {
            SecurityLevel::Standard =>
                "Basic protection — minimal overhead. Suitable for general browsing.",
            SecurityLevel::Enhanced =>
                "Enhanced protection — moderate overhead. Defends against traffic analysis and circuit fingerprinting. Default.",
            SecurityLevel::Maximum =>
                "Maximum protection — higher overhead. Full obfuscation, BGP guard, multi-path. For high-risk situations.",
        }
    }

    /// Returns the recommended CoreSettings for this level.
    pub fn recommended_core(self) -> CoreSettings {
        match self {
            SecurityLevel::Standard => CoreSettings {
                traffic_shaping:         true,
                adaptive_padding:        true,
                timing_protection:       false,
                circuit_obfuscation:     false,
                flow_correlation_defense: false,
                target_rate:             100.0,
                max_jitter_ms:           20,
                batch_size:              5,
            },
            SecurityLevel::Enhanced => CoreSettings::default(),
            SecurityLevel::Maximum => CoreSettings {
                traffic_shaping:         true,
                adaptive_padding:        true,
                timing_protection:       true,
                circuit_obfuscation:     true,
                flow_correlation_defense: true,
                target_rate:             200.0,
                max_jitter_ms:           100,
                batch_size:              20,
            },
        }
    }

    /// Returns the recommended RoutingSettings for this level.
    pub fn recommended_routing(self) -> RoutingSettings {
        match self {
            SecurityLevel::Standard => RoutingSettings {
                bgp_protection:      false,
                guard_management:    false,
                resource_protection: true,
                dns_protection:      true,
                webrtc_protection:   true,
                sybil_defense:       true,
            },
            SecurityLevel::Enhanced => RoutingSettings::default(),
            SecurityLevel::Maximum  => RoutingSettings {
                bgp_protection:      true,
                guard_management:    true,
                resource_protection: true,
                dns_protection:      true,
                webrtc_protection:   true,
                sybil_defense:       true,
            },
        }
    }

    /// Returns true if switching to `self` from `from` is a downgrade.
    pub fn is_downgrade_from(self, from: SecurityLevel) -> bool {
        // Standard < Enhanced < Maximum
        let rank = |l: SecurityLevel| match l {
            SecurityLevel::Standard => 0_u8,
            SecurityLevel::Enhanced => 1,
            SecurityLevel::Maximum  => 2,
        };
        rank(self) < rank(from)
    }

    /// Returns true if lowering to this level loses significant protections.
    pub fn is_dangerous_downgrade(self, from: SecurityLevel) -> bool {
        // Any drop to Standard is dangerous
        matches!(
            (from, self),
            (SecurityLevel::Enhanced, SecurityLevel::Standard)
            | (SecurityLevel::Maximum, SecurityLevel::Standard)
        )
    }
}

// ── CoreSettings ─────────────────────────────────────────────────────────────

/// Anti-surveillance settings (maps to gptl-core AntiSurveillanceConfig).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CoreSettings {
    /// Constant-rate cell transmission with padding (traffic confirmation defense)
    pub traffic_shaping: bool,
    /// WTF-PAD adaptive padding (website fingerprinting defense)
    pub adaptive_padding: bool,
    /// Jitter injection and packet batching (timing attack defense)
    pub timing_protection: bool,
    /// Circuit type obfuscation and preemptive padding (circuit fingerprinting defense)
    pub circuit_obfuscation: bool,
    /// DeepCorr-style flow perturbation (flow correlation defense)
    pub flow_correlation_defense: bool,
    /// Target cell transmission rate in cells/second. Higher = more cover traffic.
    pub target_rate: f64,
    /// Maximum random jitter injected per packet (milliseconds)
    pub max_jitter_ms: u64,
    /// Number of cells batched together before transmission
    pub batch_size: usize,
}

impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            traffic_shaping:          true,
            adaptive_padding:         true,
            timing_protection:        true,
            circuit_obfuscation:      true,
            flow_correlation_defense: true,
            target_rate:              100.0,
            max_jitter_ms:            50,
            batch_size:               10,
        }
    }
}

// ── RoutingSettings ───────────────────────────────────────────────────────────

/// Network-layer defense settings (maps to gptl-routing RoutingConfig).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RoutingSettings {
    /// RPKI route validation and AS-aware path selection (BGP hijacking defense)
    pub bgp_protection: bool,
    /// Vanguard layered guard architecture (guard discovery defense)
    pub guard_management: bool,
    /// Memory pool limits and proof-of-work circuit creation (sniper attack defense)
    pub resource_protection: bool,
    /// DNS-over-HTTPS/TLS and DNS firewall (DNS leak prevention)
    pub dns_protection: bool,
    /// ICE candidate filtering and TURN relay enforcement (WebRTC leak prevention)
    pub webrtc_protection: bool,
    /// Reputation-based relay validation and behavioral detection (Sybil defense)
    pub sybil_defense: bool,
}

impl Default for RoutingSettings {
    fn default() -> Self {
        Self {
            bgp_protection:      true,
            guard_management:    true,
            resource_protection: true,
            dns_protection:      true,
            webrtc_protection:   true,
            sybil_defense:       true,
        }
    }
}

// ── GptlConfig ────────────────────────────────────────────────────────────────

/// Top-level GPTL configuration persisted at `~/.config/gptl/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GptlConfig {
    /// Active security level label
    pub security_level: SecurityLevel,
    /// Anti-surveillance (gptl-core) settings
    pub core: CoreSettings,
    /// Network routing defenses (gptl-routing) settings
    pub routing: RoutingSettings,
}

impl Default for GptlConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::Enhanced,
            core:           CoreSettings::default(),
            routing:        RoutingSettings::default(),
        }
    }
}

impl GptlConfig {
    // ── Filesystem ──────────────────────────────────────────────────────────

    /// Returns the platform-appropriate default config path.
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let base = dirs::config_dir().ok_or(ConfigError::NoDirFound)?;
        Ok(base.join("gptl").join("config.toml"))
    }

    /// Loads config from `path`. Creates a default file if it does not exist.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            let cfg = GptlConfig::default();
            cfg.save(path)?;
            return Ok(cfg);
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: GptlConfig = toml::from_str(&text)?;
        Ok(cfg)
    }

    /// Saves the config to `path`, creating parent directories as needed.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    // ── Key/value interface ─────────────────────────────────────────────────

    /// Returns all settable keys with their current value and a short description.
    pub fn all_keys(&self) -> Vec<(String, String, &'static str)> {
        vec![
            ("security_level".into(),               self.security_level.to_string(), "standard | enhanced | maximum"),
            ("core.traffic_shaping".into(),          self.core.traffic_shaping.to_string(),          "true/false — traffic confirmation defense"),
            ("core.adaptive_padding".into(),         self.core.adaptive_padding.to_string(),         "true/false — website fingerprinting defense"),
            ("core.timing_protection".into(),        self.core.timing_protection.to_string(),        "true/false — timing attack defense"),
            ("core.circuit_obfuscation".into(),      self.core.circuit_obfuscation.to_string(),      "true/false — circuit fingerprinting defense"),
            ("core.flow_correlation_defense".into(), self.core.flow_correlation_defense.to_string(), "true/false — flow correlation defense"),
            ("core.target_rate".into(),              self.core.target_rate.to_string(),              "float  — cover traffic rate (cells/second)"),
            ("core.max_jitter_ms".into(),            self.core.max_jitter_ms.to_string(),            "integer — max jitter in milliseconds"),
            ("core.batch_size".into(),               self.core.batch_size.to_string(),               "integer — cell batch size"),
            ("routing.bgp_protection".into(),        self.routing.bgp_protection.to_string(),        "true/false — BGP hijacking defense"),
            ("routing.guard_management".into(),      self.routing.guard_management.to_string(),      "true/false — guard discovery defense"),
            ("routing.resource_protection".into(),   self.routing.resource_protection.to_string(),   "true/false — sniper attack defense"),
            ("routing.dns_protection".into(),        self.routing.dns_protection.to_string(),        "true/false — DNS leak prevention"),
            ("routing.webrtc_protection".into(),     self.routing.webrtc_protection.to_string(),     "true/false — WebRTC leak prevention"),
            ("routing.sybil_defense".into(),         self.routing.sybil_defense.to_string(),         "true/false — Sybil attack defense"),
        ]
    }

    /// Returns true if changing this key requires a security confirmation.
    pub fn is_security_sensitive(key: &str) -> bool {
        matches!(
            key,
            "security_level"
                | "core.traffic_shaping"
                | "core.adaptive_padding"
                | "core.timing_protection"
                | "core.circuit_obfuscation"
                | "core.flow_correlation_defense"
                | "routing.bgp_protection"
                | "routing.guard_management"
                | "routing.resource_protection"
                | "routing.dns_protection"
                | "routing.webrtc_protection"
                | "routing.sybil_defense"
        )
    }

    /// Returns true if this is a potentially dangerous change (disabling a protection or
    /// downgrading to Standard).
    pub fn is_dangerous_change(key: &str, new_value: &str) -> bool {
        if Self::is_security_sensitive(key) && matches!(new_value, "false" | "0" | "no" | "off") {
            return true;
        }
        key == "security_level" && new_value == "standard"
    }

    /// Sets a key by dot-notation path. Returns the previous value as a String.
    pub fn set_key(&mut self, key: &str, value: &str) -> Result<String, ConfigError> {
        let old = self.get_key(key)?;
        match key {
            "security_level" => {
                self.security_level = value.parse()?;
            }
            "core.traffic_shaping" => {
                self.core.traffic_shaping = parse_bool(key, value)?;
            }
            "core.adaptive_padding" => {
                self.core.adaptive_padding = parse_bool(key, value)?;
            }
            "core.timing_protection" => {
                self.core.timing_protection = parse_bool(key, value)?;
            }
            "core.circuit_obfuscation" => {
                self.core.circuit_obfuscation = parse_bool(key, value)?;
            }
            "core.flow_correlation_defense" => {
                self.core.flow_correlation_defense = parse_bool(key, value)?;
            }
            "core.target_rate" => {
                let r: f64 = value.parse().map_err(|_| ConfigError::InvalidValue {
                    key: key.to_string(),
                    message: format!("expected a positive number, got '{}'", value),
                })?;
                if r <= 0.0 {
                    return Err(ConfigError::InvalidValue {
                        key: key.to_string(),
                        message: "must be greater than zero".to_string(),
                    });
                }
                self.core.target_rate = r;
            }
            "core.max_jitter_ms" => {
                self.core.max_jitter_ms = value.parse().map_err(|_| ConfigError::InvalidValue {
                    key: key.to_string(),
                    message: format!("expected a non-negative integer, got '{}'", value),
                })?;
            }
            "core.batch_size" => {
                let n: usize = value.parse().map_err(|_| ConfigError::InvalidValue {
                    key: key.to_string(),
                    message: format!("expected a positive integer, got '{}'", value),
                })?;
                if n == 0 {
                    return Err(ConfigError::InvalidValue {
                        key: key.to_string(),
                        message: "must be at least 1".to_string(),
                    });
                }
                self.core.batch_size = n;
            }
            "routing.bgp_protection" => {
                self.routing.bgp_protection = parse_bool(key, value)?;
            }
            "routing.guard_management" => {
                self.routing.guard_management = parse_bool(key, value)?;
            }
            "routing.resource_protection" => {
                self.routing.resource_protection = parse_bool(key, value)?;
            }
            "routing.dns_protection" => {
                self.routing.dns_protection = parse_bool(key, value)?;
            }
            "routing.webrtc_protection" => {
                self.routing.webrtc_protection = parse_bool(key, value)?;
            }
            "routing.sybil_defense" => {
                self.routing.sybil_defense = parse_bool(key, value)?;
            }
            _ => return Err(ConfigError::UnknownKey(key.to_string())),
        }
        Ok(old)
    }

    /// Gets the string value of a key.
    pub fn get_key(&self, key: &str) -> Result<String, ConfigError> {
        let v = match key {
            "security_level"                => self.security_level.to_string(),
            "core.traffic_shaping"          => self.core.traffic_shaping.to_string(),
            "core.adaptive_padding"         => self.core.adaptive_padding.to_string(),
            "core.timing_protection"        => self.core.timing_protection.to_string(),
            "core.circuit_obfuscation"      => self.core.circuit_obfuscation.to_string(),
            "core.flow_correlation_defense" => self.core.flow_correlation_defense.to_string(),
            "core.target_rate"              => self.core.target_rate.to_string(),
            "core.max_jitter_ms"            => self.core.max_jitter_ms.to_string(),
            "core.batch_size"               => self.core.batch_size.to_string(),
            "routing.bgp_protection"        => self.routing.bgp_protection.to_string(),
            "routing.guard_management"      => self.routing.guard_management.to_string(),
            "routing.resource_protection"   => self.routing.resource_protection.to_string(),
            "routing.dns_protection"        => self.routing.dns_protection.to_string(),
            "routing.webrtc_protection"     => self.routing.webrtc_protection.to_string(),
            "routing.sybil_defense"         => self.routing.sybil_defense.to_string(),
            _ => return Err(ConfigError::UnknownKey(key.to_string())),
        };
        Ok(v)
    }

    /// Returns a list of (key, old_value, new_value) for every field that differs
    /// between `self` and `other`.
    pub fn diff(&self, other: &GptlConfig) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        macro_rules! chk {
            ($key:expr, $a:expr, $b:expr) => {{
                let a = $a.to_string();
                let b = $b.to_string();
                if a != b {
                    out.push(($key.to_string(), a, b));
                }
            }};
        }
        chk!("security_level",               self.security_level,               other.security_level);
        chk!("core.traffic_shaping",         self.core.traffic_shaping,         other.core.traffic_shaping);
        chk!("core.adaptive_padding",        self.core.adaptive_padding,        other.core.adaptive_padding);
        chk!("core.timing_protection",       self.core.timing_protection,       other.core.timing_protection);
        chk!("core.circuit_obfuscation",     self.core.circuit_obfuscation,     other.core.circuit_obfuscation);
        chk!("core.flow_correlation_defense",self.core.flow_correlation_defense,other.core.flow_correlation_defense);
        chk!("core.target_rate",             self.core.target_rate,             other.core.target_rate);
        chk!("core.max_jitter_ms",           self.core.max_jitter_ms,           other.core.max_jitter_ms);
        chk!("core.batch_size",              self.core.batch_size,              other.core.batch_size);
        chk!("routing.bgp_protection",       self.routing.bgp_protection,       other.routing.bgp_protection);
        chk!("routing.guard_management",     self.routing.guard_management,     other.routing.guard_management);
        chk!("routing.resource_protection",  self.routing.resource_protection,  other.routing.resource_protection);
        chk!("routing.dns_protection",       self.routing.dns_protection,       other.routing.dns_protection);
        chk!("routing.webrtc_protection",    self.routing.webrtc_protection,    other.routing.webrtc_protection);
        chk!("routing.sybil_defense",        self.routing.sybil_defense,        other.routing.sybil_defense);
        out
    }

    /// Returns the number of protections currently disabled.
    pub fn disabled_count(&self) -> usize {
        [
            self.core.traffic_shaping,
            self.core.adaptive_padding,
            self.core.timing_protection,
            self.core.circuit_obfuscation,
            self.core.flow_correlation_defense,
            self.routing.bgp_protection,
            self.routing.guard_management,
            self.routing.resource_protection,
            self.routing.dns_protection,
            self.routing.webrtc_protection,
            self.routing.sybil_defense,
        ]
        .iter()
        .filter(|&&b| !b)
        .count()
    }

    /// Total number of boolean protection flags.
    pub const TOTAL_PROTECTIONS: usize = 11;
}

// ── helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on"  => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidValue {
            key: key.to_string(),
            message: format!("expected true or false, got '{}'", value),
        }),
    }
}
