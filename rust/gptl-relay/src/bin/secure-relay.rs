//! GPTL Secure Relay Server
//!
//! Multi-layer authentication and access control relay server
//! with enterprise-grade security features.
//!
//! ## Security Layers
//!
//! 1. Multi-Factor Authentication (MFA)
//!    - Password + TOTP (RFC 6238)
//!    - FIDO2/WebAuthn hardware tokens
//!    - Client certificate authentication (mTLS)
//!
//! 2. IP-Based Access Control
//!    - IP allowlist/blocklist (CIDR support)
//!    - Geolocation blocking (MaxMind GeoIP2)
//!    - Threat intelligence integration
//!
//! 3. Rate Limiting & Anti-Brute Force
//!    - Exponential backoff on failures
//!    - Account lockout after N failures
//!    - CAPTCHA challenges
//!
//! 4. Session Management
//!    - Short-lived JWT tokens (15 min default)
//!    - Session binding to IP + fingerprint
//!    - Automatic expiration
//!
//! 5. API Key System
//!    - Scoped permissions (read-only, admin, relay)
//!    - Key rotation support
//!    - Key expiration
//!
//! 6. Audit Logging
//!    - Tamper-evident Merkle tree logs
//!    - All auth attempts logged
//!    - Admin action audit trail

use gptl_relay::{
    auth::{MfaAuthenticator, PasswordHasher, TotpManager, WebAuthnManager, ClientCertVerifier},
    ip_restriction::{IpAllowlist, GeoBlocker, ThreatIntelligence},
    rate_limit::AuthRateLimiter,
    session::SessionManager,
    api_key::ApiKeyManager,
    audit::AuditLogger,
    relay::{RelayServer, RelayConfig},
    config::{ServerConfig, load_config},
    SecurityFeatures,
};
use tracing::{info, warn, error};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("gptl_relay=info,warn,error")
        .init();

    info!("Starting GPTL Secure Relay Server");
    info!("Version: {}", gptl_relay::VERSION);

    // Load configuration
    let config = match load_config() {
        Ok(cfg) => {
            info!("Configuration loaded successfully");
            cfg
        }
        Err(e) => {
            warn!("Failed to load configuration: {}. Using defaults.", e);
            ServerConfig::default()
        }
    };

    // Initialize security components
    info!("Initializing security components...");

    // 1. Multi-Factor Authentication
    let password_hasher = PasswordHasher::secure();
    let totp_manager = TotpManager::default();
    let mut auth = MfaAuthenticator::new(password_hasher, totp_manager);

    // Add WebAuthn support if configured
    if config.auth.webauthn_enabled {
        match WebAuthnManager::new(
            "GPTL Secure Relay",
            "relay.gptl.local",
            "https://relay.gptl.local",
        ) {
            Ok(webauthn) => {
                auth = auth.with_webauthn(webauthn);
                info!("  ✓ WebAuthn/FIDO2 hardware token support enabled");
            }
            Err(e) => {
                warn!("  ✗ Failed to initialize WebAuthn: {}", e);
            }
        }
    }

    // Add client certificate support if configured
    if config.auth.client_cert_enabled {
        let cert_verifier = ClientCertVerifier::new();
        auth = auth.with_client_certs(cert_verifier);
        info!("  ✓ Client certificate (mTLS) authentication enabled");
    }

    // 2. IP Restrictions
    let mut ip_allowlist = IpAllowlist::new();
    
    if config.security.geoblocking_enabled {
        let geo_blocker = GeoBlocker::new()
            .block_tor_exit_nodes()
            .block_vpns_and_proxies();
        ip_allowlist = ip_allowlist.with_geoblocking(geo_blocker);
        info!("  ✓ Geolocation blocking enabled");
    }

    if config.security.threat_intel_enabled {
        let threat_intel = ThreatIntelligence::new();
        ip_allowlist = ip_allowlist.with_threat_intel(threat_intel);
        info!("  ✓ Threat intelligence integration enabled");
    }

    // 3. Rate Limiting
    let rate_limiter = AuthRateLimiter::new();
    info!("  ✓ Rate limiting and anti-brute force protection enabled");

    // 4. Session Management
    let session_manager = SessionManager::new(&generate_signing_key())
        .with_access_ttl(config.session.access_token_ttl_minutes)
        .with_refresh_ttl(config.session.refresh_token_ttl_days);
    info!("  ✓ Session management enabled ({} min access, {} day refresh)",
          config.session.access_token_ttl_minutes,
          config.session.refresh_token_ttl_days);

    // 5. API Key Management
    let api_key_manager = ApiKeyManager::new();
    info!("  ✓ API key system enabled");

    // 6. Audit Logging
    let audit_logger = AuditLogger::new(generate_signing_key())
        .with_persistent_storage("/var/log/gptl/audit.log");
    info!("  ✓ Tamper-evident audit logging enabled");

    // Create relay server
    let relay_config = RelayConfig {
        bind_address: config.server.bind_address.clone(),
        tls_cert_path: config.server.tls_cert_path.clone(),
        tls_key_path: config.server.tls_key_path.clone(),
        mtls_enabled: config.security.require_client_cert,
        mtls_ca_path: config.security.require_client_cert.then(|| "/etc/gptl/ca.crt".to_string()),
        request_timeout_secs: config.server.request_timeout_secs,
        max_connections: config.server.max_connections,
        strict_mode: config.security.level == gptl_relay::SecurityLevel::Maximum,
    };

    let server = RelayServer::new(relay_config)
        .with_auth(auth)
        .with_ip_allowlist(ip_allowlist)
        .with_rate_limiter(rate_limiter)
        .with_session_manager(session_manager)
        .with_api_key_manager(api_key_manager)
        .with_audit_logger(audit_logger);

    // Print security features summary
    print_security_summary(&config);

    // Start server
    info!("Relay server starting on {}", config.server.bind_address);
    
    if let Err(e) = server.start().await {
        error!("Server error: {}", e);
        return Err(Box::new(e) as Box<dyn std::error::Error>);
    }

    Ok(())
}

/// Print security features summary
fn print_security_summary(config: &ServerConfig) {
    let features = config.security.level.features();
    
    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║              SECURITY FEATURES ENABLED                       ║");
    info!("╠══════════════════════════════════════════════════════════════╣");
    info!("║ Multi-Factor Authentication: {:31} ║", 
          if features.mfa_enabled { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Hardware Token Support:      {:31} ║", 
          if features.hardware_tokens { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Client Certificate Auth:     {:31} ║", 
          if features.client_certs { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ IP Restrictions:             {:31} ║", 
          if features.ip_restrictions { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Geolocation Blocking:        {:31} ║", 
          if features.geoblocking { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Rate Limiting:               {:31} ║", 
          if features.rate_limiting { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Account Lockout:             {:31} ║", 
          if features.account_lockout { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ CAPTCHA Support:             {:31} ║", 
          if features.captcha { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Session Binding:             {:31} ║", 
          if features.session_binding { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ API Key System:              {:31} ║", 
          if features.api_keys { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Audit Logging:               {:31} ║", 
          if features.audit_logging { "✓ ENABLED" } else { "✗ Disabled" });
    info!("║ Tamper-Evident Logs:         {:31} ║", 
          if features.tamper_evident { "✓ ENABLED" } else { "✗ Disabled" });
    info!("╚══════════════════════════════════════════════════════════════╝");
}

/// Generate a secure signing key
fn generate_signing_key() -> Vec<u8> {
    use rand::RngCore;
    
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}
