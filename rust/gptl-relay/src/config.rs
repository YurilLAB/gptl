//! Configuration Management
//!
//! Server configuration with environment variable support and validation:
//! - TOML configuration files
//! - Environment variable overrides
//! - Configuration validation
//! - Secure defaults

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Server settings
    pub server: ServerSettings,
    /// Security settings
    pub security: SecurityConfig,
    /// Authentication settings
    pub auth: AuthConfig,
    /// Rate limiting settings
    pub rate_limit: RateLimitSettings,
    /// Session settings
    pub session: SessionSettings,
    /// Audit log settings
    pub audit: AuditSettings,
}

impl ServerConfig {
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| crate::RelayError::ConfigError(
                format!("Failed to read config file: {}", e)
            ))?;
        
        Self::from_toml(&contents)
    }

    /// Load configuration from TOML string
    pub fn from_toml(toml: &str) -> crate::Result<Self> {
        toml::from_str(toml)
            .map_err(|e| crate::RelayError::ConfigError(
                format!("Invalid TOML: {}", e)
            ))
    }

    /// Load with environment variable overrides
    pub fn from_file_with_env<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let mut config = Self::from_file(path)?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Server settings
        if let Ok(addr) = std::env::var("GPTL_BIND_ADDRESS") {
            self.server.bind_address = addr;
        }
        if let Ok(port) = std::env::var("GPTL_PORT") {
            self.server.bind_address = format!("0.0.0.0:{}", port);
        }

        // Security settings
        if let Ok(level) = std::env::var("GPTL_SECURITY_LEVEL") {
            self.security.level = match level.as_str() {
                "maximum" => SecurityLevel::Maximum,
                "enhanced" => SecurityLevel::Enhanced,
                _ => SecurityLevel::Standard,
            };
        }

        // Auth settings
        if let Ok(true) = std::env::var("GPTL_MFA_REQUIRED")
            .map(|v| v.parse::<bool>().unwrap_or(false)) {
            self.auth.mfa_required = true;
        }

        // Session settings
        if let Ok(ttl) = std::env::var("GPTL_SESSION_TTL_MINUTES") {
            if let Ok(minutes) = ttl.parse::<i64>() {
                self.session.access_token_ttl_minutes = minutes;
            }
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::Result<()> {
        // Validate server settings
        if self.server.bind_address.is_empty() {
            return Err(crate::RelayError::ConfigError(
                "Bind address cannot be empty".to_string()
            ));
        }

        // Validate auth settings
        if self.auth.password_min_length < 8 {
            return Err(crate::RelayError::ConfigError(
                "Password minimum length must be at least 8".to_string()
            ));
        }

        // Validate session settings
        if self.session.access_token_ttl_minutes < 5 {
            return Err(crate::RelayError::ConfigError(
                "Session TTL must be at least 5 minutes".to_string()
            ));
        }

        Ok(())
    }

    /// Get default configuration
    pub fn default_config() -> Self {
        Self {
            server: ServerSettings::default(),
            security: SecurityConfig::default(),
            auth: AuthConfig::default(),
            rate_limit: RateLimitSettings::default(),
            session: SessionSettings::default(),
            audit: AuditSettings::default(),
        }
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let toml = toml::to_string_pretty(self)
            .map_err(|e| crate::RelayError::ConfigError(
                format!("Failed to serialize config: {}", e)
            ))?;
        
        std::fs::write(path, toml)
            .map_err(|e| crate::RelayError::ConfigError(
                format!("Failed to write config file: {}", e)
            ))
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

fn default_bind_address() -> String { "0.0.0.0:8443".to_string() }
fn default_workers() -> usize { num_cpus::get() }
fn default_request_timeout_secs() -> u64 { 30 }
fn default_max_connections() -> usize { 10000 }

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8443".to_string(),
            workers: num_cpus::get(),
            request_timeout_secs: 30,
            max_connections: 10000,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub level: SecurityLevel,
    pub ip_allowlist_enabled: bool,
    pub geoblocking_enabled: bool,
    pub threat_intel_enabled: bool,
    pub require_client_cert: bool,
    pub strict_headers: bool,
    pub hsts_max_age: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            level: SecurityLevel::Enhanced,
            ip_allowlist_enabled: true,
            geoblocking_enabled: false,
            threat_intel_enabled: true,
            require_client_cert: false,
            strict_headers: true,
            hsts_max_age: 31536000, // 1 year
        }
    }
}

/// Security level
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityLevel {
    /// Standard security (balanced)
    Standard,
    /// Enhanced security (recommended)
    Enhanced,
    /// Maximum security (paranoid)
    Maximum,
}

impl SecurityLevel {
    /// Get features for this security level
    pub fn features(&self) -> crate::SecurityFeatures {
        match self {
            SecurityLevel::Standard => crate::SecurityFeatures::balanced(),
            SecurityLevel::Enhanced => crate::SecurityFeatures::default(),
            SecurityLevel::Maximum => crate::SecurityFeatures::maximum(),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub mfa_required: bool,
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    pub client_cert_enabled: bool,
    pub password_min_length: usize,
    pub password_require_special: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration_minutes: i64,
    pub captcha_after_failures: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mfa_required: true,
            totp_enabled: true,
            webauthn_enabled: true,
            client_cert_enabled: false,
            password_min_length: 12,
            password_require_special: true,
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            captcha_after_failures: 3,
        }
    }
}

/// Rate limit settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitSettings {
    pub enabled: bool,
    pub requests_per_ip_per_minute: u32,
    pub requests_per_user_per_minute: u32,
    pub login_attempts_per_ip: u32,
    pub login_attempts_per_user: u32,
    pub exponential_backoff: bool,
    pub max_backoff_minutes: u64,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_ip_per_minute: 100,
            requests_per_user_per_minute: 60,
            login_attempts_per_ip: 10,
            login_attempts_per_user: 5,
            exponential_backoff: true,
            max_backoff_minutes: 60,
        }
    }
}

/// Session settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionSettings {
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
    pub session_binding_enabled: bool,
    pub max_sessions_per_user: usize,
    pub idle_timeout_minutes: i64,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            access_token_ttl_minutes: 15,
            refresh_token_ttl_days: 7,
            session_binding_enabled: true,
            max_sessions_per_user: 5,
            idle_timeout_minutes: 30,
        }
    }
}

/// Audit log settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditSettings {
    pub enabled: bool,
    pub log_level: String,
    pub log_to_file: bool,
    pub log_file_path: String,
    pub log_to_syslog: bool,
    pub tamper_evident: bool,
    pub retention_days: u32,
}

impl Default for AuditSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "info".to_string(),
            log_to_file: true,
            log_file_path: "/var/log/gptl-relay/audit.log".to_string(),
            log_to_syslog: false,
            tamper_evident: true,
            retention_days: 365,
        }
    }
}

/// Load configuration with defaults
pub fn load_config() -> crate::Result<ServerConfig> {
    // Try config file locations in order
    let config_paths = [
        "gptl-relay.toml",
        "/etc/gptl-relay/config.toml",
        "/etc/gptl/gptl-relay.toml",
    ];

    for path in &config_paths {
        if std::path::Path::new(path).exists() {
            return ServerConfig::from_file_with_env(path);
        }
    }

    // Return default configuration
    Ok(ServerConfig::default())
}

/// Generate example configuration
pub fn generate_example_config() -> String {
    let config = ServerConfig::default();
    toml::to_string_pretty(&config).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.server.bind_address, "0.0.0.0:8443");
        assert!(config.auth.mfa_required);
        assert!(config.rate_limit.enabled);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
[server]
bind_address = "127.0.0.1:8080"

[security]
level = "maximum"

[auth]
mfa_required = true
password_min_length = 16
"#;

        let config = ServerConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.bind_address, "127.0.0.1:8080");
        assert_eq!(config.security.level, SecurityLevel::Maximum);
        assert_eq!(config.auth.password_min_length, 16);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ServerConfig::default();
        assert!(config.validate().is_ok());

        // Invalid password length
        config.auth.password_min_length = 4;
        assert!(config.validate().is_err());

        // Reset and test invalid session TTL
        config.auth.password_min_length = 12;
        config.session.access_token_ttl_minutes = 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_security_level_features() {
        let standard = SecurityLevel::Standard;
        let enhanced = SecurityLevel::Enhanced;
        let maximum = SecurityLevel::Maximum;

        assert!(!standard.features().hardware_tokens);
        assert!(enhanced.features().mfa_enabled);
        assert!(maximum.features().tamper_evident);
    }
}
