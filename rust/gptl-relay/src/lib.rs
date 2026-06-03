//! GPTL Relay Library
//!
//! Multi-layer authentication and access control relay server
//! with enterprise-grade security features.

#![warn(missing_docs)]

use std::net::IpAddr;

// Module declarations
pub mod api_key;
pub mod audit;
pub mod auth;
pub mod auto_setup;
pub mod config;
pub mod ip_restriction;
pub mod rate_limit;
pub mod relay;
pub mod session;

/// Re-export change tracking from gptl-core for use by the CLI binary
pub mod changes {
    pub use gptl_core::changes::*;
}

// Re-export commonly used types
pub use api_key::{ApiKeyCredentials, ApiKeyInfo, ApiKeyManager, ApiKeyScope, ApiKeyValidation};
pub use audit::{AuditLogger, AuthEvent, SecurityEventType, SecuritySeverity};
pub use auth::{
    AuthStep, ClientCertVerifier, MfaAuthenticator, PasswordHasher, TotpManager, WebAuthnManager,
};
pub use auto_setup::{
    FirewallAutomation, FirewallError, FirewallResult, FirewallStatus, FirewallType, TrackedRule,
};
pub use config::{load_config, SecurityLevel, ServerConfig};
pub use ip_restriction::{GeoBlocker, IpAllowlist, ThreatIntelligence};
pub use rate_limit::AuthRateLimiter;
pub use relay::{RelayConfig, RelayServer};
pub use session::SessionManager;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result type for relay operations
pub type Result<T> = std::result::Result<T, RelayError>;

/// Error types for relay operations
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization failed
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    /// Invalid session
    #[error("Invalid session")]
    InvalidSession,

    /// Session binding mismatch
    #[error("Session binding mismatch: {0}")]
    SessionBindingMismatch(String),

    /// IP is blocked
    #[error("IP blocked: {0}")]
    IpBlocked(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded. Retry after {0} seconds")]
    RateLimitExceeded(u64),

    /// Account is locked
    #[error("Account locked: {0}")]
    AccountLocked(String),

    /// Invalid API key
    #[error("Invalid API key")]
    InvalidApiKey,

    /// API key expired
    #[error("API key expired")]
    ApiKeyExpired,

    /// Audit error
    #[error("Audit error: {0}")]
    AuditError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Security context for requests
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Client IP address
    pub client_ip: IpAddr,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// Session ID (if authenticated)
    pub session_id: Option<String>,
    /// API key ID (if authenticated via API key)
    pub api_key_id: Option<String>,
    /// Client fingerprint (legacy field)
    pub fingerprint: Option<String>,
    /// Client fingerprint (detailed field)
    pub client_fingerprint: Option<String>,
    /// Request ID
    pub request_id: String,
}

impl SecurityContext {
    /// Create a new security context for a client IP
    pub fn new(client_ip: IpAddr) -> Self {
        Self {
            client_ip,
            user_id: None,
            session_id: None,
            api_key_id: None,
            fingerprint: None,
            client_fingerprint: None,
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Add user information to the context
    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    /// Add fingerprint to the context
    pub fn with_fingerprint(mut self, fingerprint: &str) -> Self {
        self.fingerprint = Some(fingerprint.to_string());
        self.client_fingerprint = Some(fingerprint.to_string());
        self
    }

    /// Add API key ID to the context
    pub fn with_api_key(mut self, key_id: &str) -> Self {
        self.api_key_id = Some(key_id.to_string());
        self
    }
}

/// Security features configuration
#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    /// Multi-factor authentication enabled
    pub mfa_enabled: bool,
    /// Hardware token support
    pub hardware_tokens: bool,
    /// Client certificate authentication
    pub client_certs: bool,
    /// IP restrictions
    pub ip_restrictions: bool,
    /// Geolocation blocking
    pub geoblocking: bool,
    /// Rate limiting
    pub rate_limiting: bool,
    /// Account lockout
    pub account_lockout: bool,
    /// CAPTCHA support
    pub captcha: bool,
    /// Session binding
    pub session_binding: bool,
    /// API key system
    pub api_keys: bool,
    /// Audit logging
    pub audit_logging: bool,
    /// Tamper-evident logs
    pub tamper_evident: bool,
}

impl SecurityFeatures {
    /// Balanced security features (standard level)
    pub fn balanced() -> Self {
        Self {
            mfa_enabled: true,
            hardware_tokens: false,
            client_certs: false,
            ip_restrictions: true,
            geoblocking: false,
            rate_limiting: true,
            account_lockout: true,
            captcha: false,
            session_binding: true,
            api_keys: true,
            audit_logging: true,
            tamper_evident: false,
        }
    }

    /// Maximum security features
    pub fn maximum() -> Self {
        Self {
            mfa_enabled: true,
            hardware_tokens: true,
            client_certs: true,
            ip_restrictions: true,
            geoblocking: true,
            rate_limiting: true,
            account_lockout: true,
            captcha: true,
            session_binding: true,
            api_keys: true,
            audit_logging: true,
            tamper_evident: true,
        }
    }
}

impl Default for SecurityFeatures {
    fn default() -> Self {
        // Enhanced security (recommended)
        Self {
            mfa_enabled: true,
            hardware_tokens: true,
            client_certs: false,
            ip_restrictions: true,
            geoblocking: false,
            rate_limiting: true,
            account_lockout: true,
            captcha: true,
            session_binding: true,
            api_keys: true,
            audit_logging: true,
            tamper_evident: true,
        }
    }
}
