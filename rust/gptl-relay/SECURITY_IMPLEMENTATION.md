# GPTL Relay Server - Security Implementation

## Overview

This document describes the comprehensive multi-layer security implementation for the GPTL Relay Server. The security architecture is inspired by SSH, Tor, and enterprise VPN access control systems.

## Security Layers

### 1. Multi-Factor Authentication (MFA)

#### Password + TOTP (Time-Based One-Time Password)
- **RFC 6238 compliant** TOTP implementation
- 30-second time step (configurable)
- Support for SHA-1, SHA-256, SHA-512 hash algorithms
- Configurable digit count (6 or 8)
- Backup codes for account recovery
- QR code provisioning URI generation

#### Hardware Token Support (FIDO2/WebAuthn)
- **FIDO2/WebAuthn** authentication for hardware security keys
- YubiKey, Titan Security Key, and compatible devices
- Resident keys (passkeys) support
- Attestation verification
- Counter verification for clone detection
- Challenge-response authentication flow

#### Client Certificate Authentication (mTLS)
- X.509 client certificate verification
- Certificate chain validation
- Certificate pinning support
- CRL (Certificate Revocation List) checking
- Fingerprint-based certificate identification
- Self-signed certificate support (testing only)

**Implementation Files:**
- `src/auth/mod.rs` - Core MFA orchestrator
- `src/auth/totp.rs` - TOTP implementation
- `src/auth/webauthn.rs` - FIDO2/WebAuthn support
- `src/auth/client_cert.rs` - Client certificate auth
- `src/auth/password.rs` - Argon2id password hashing

### 2. IP-Based Restrictions

#### IP Allowlist/Blocklist
- CIDR notation support for range-based rules
- IPv4 and IPv6 support
- Default-deny and default-allow modes
- Per-IP metadata and blocking reasons
- Automatic block expiration

#### Geolocation Blocking (MaxMind GeoIP2)
- Country code blocking (ISO 3166-1 alpha-2)
- ASN (Autonomous System Number) filtering
- Continent-level filtering
- Tor exit node detection and blocking
- VPN/proxy detection
- Hosting provider detection
- Sanctioned country detection (OFAC)
- GDPR jurisdiction detection

#### Threat Intelligence
- AbuseIPDB integration
- VirusTotal IP reputation
- AlienVault OTX integration
- Custom threat feed support
- C2 (Command & Control) detection
- Automatic threat-based blocking
- Configurable threat score thresholds

**Implementation Files:**
- `src/ip_restriction/mod.rs` - IP allowlist/blocklist
- `src/ip_restriction/geolocation.rs` - Geo-blocking
- `src/ip_restriction/threat_intel.rs` - Threat intelligence

### 3. Rate Limiting & Anti-Brute Force

#### Exponential Backoff
- Progressive delay on failed authentication
- Configurable base delay and maximum backoff
- Per-IP and per-account tracking
- Automatic backoff reset on success

#### Account Lockout
- Configurable failure threshold
- Progressive lockout duration (doubles each time)
- Maximum lockout cap (default: 24 hours)
- Administrative unlock capability
- Lockout notification

#### CAPTCHA Integration
- hCaptcha support
- Configurable challenge threshold
- Challenge timeout handling
- Fallback text-based CAPTCHA

**Implementation Files:**
- `src/rate_limit/mod.rs` - Core rate limiting
- `src/rate_limit/governor.rs` - Token bucket rate limiting
- `src/rate_limit/captcha.rs` - CAPTCHA challenges

### 4. Session Management

#### Short-Lived JWT Tokens
- Access tokens: 15 minutes default TTL
- Refresh tokens: 7 days default TTL
- RS256/HS256 signature algorithms
- Configurable token lifetime

#### Session Binding
- IP address binding
- Device fingerprint binding
- TLS session binding
- Automatic session invalidation on mismatch

#### Automatic Expiration
- Sliding window refresh
- Absolute timeout support
- Idle timeout detection
- Concurrent session limits

**Implementation Files:**
- `src/session/mod.rs` - Session management

### 5. API Key System

#### Scoped API Keys
Available scopes:
- `read_only` - Read-only access
- `read_write` - Read and write access
- `relay` - Relay operations
- `admin` - Full administrative access
- `audit` - Audit log access
- `users` - User management
- `config` - Configuration management

#### Key Rotation
- Automatic rotation support
- Grace period for old keys
- Rotation audit logging
- Parent-child key tracking

#### Key Expiration
- Configurable TTL per key
- Default 365-day expiration
- Expiration warnings
- Automatic cleanup of expired keys

**Implementation Files:**
- `src/api_key/mod.rs` - API key management

### 6. Audit Logging

#### Tamper-Evident Logging
- **Merkle tree** chain structure
- Cryptographic hash chaining (SHA-256)
- HMAC-SHA256 entry signatures
- Integrity verification on demand

#### Logged Events
- All authentication attempts (success/failure)
- Administrative actions
- Configuration changes
- Session events (create, refresh, revoke)
- Security events (threats, blocks)
- API key usage

#### Log Features
- Structured JSON logging
- Sequence numbers for ordering
- Timestamp precision (milliseconds)
- Full security context
- Export capabilities

**Implementation Files:**
- `src/audit/mod.rs` - Audit logging

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GPTL_BIND_ADDRESS` | Server bind address | `0.0.0.0:8443` |
| `GPTL_PORT` | Server port | `8443` |
| `GPTL_SECURITY_LEVEL` | Security level (standard/enhanced/maximum) | `enhanced` |
| `GPTL_MFA_REQUIRED` | Require MFA for all users | `true` |
| `GPTL_SESSION_TTL_MINUTES` | Access token TTL | `15` |

### Configuration File Example

```toml
[server]
bind_address = "0.0.0.0:8443"
workers = 4
request_timeout_secs = 30
max_connections = 10000
tls_cert_path = "/etc/gptl/server.crt"
tls_key_path = "/etc/gptl/server.key"

[security]
level = "enhanced"
ip_allowlist_enabled = true
geoblocking_enabled = false
threat_intel_enabled = true
require_client_cert = false
strict_headers = true

[auth]
mfa_required = true
totp_enabled = true
webauthn_enabled = true
client_cert_enabled = false
password_min_length = 12
password_require_special = true
max_failed_attempts = 5
lockout_duration_minutes = 15

[rate_limit]
enabled = true
requests_per_ip_per_minute = 100
requests_per_user_per_minute = 60
exponential_backoff = true

[session]
access_token_ttl_minutes = 15
refresh_token_ttl_days = 7
session_binding_enabled = true
max_sessions_per_user = 5

[audit]
enabled = true
log_level = "info"
tamper_evident = true
retention_days = 365
```

## Security Features by Level

### Standard (Balanced)
- MFA with password + TOTP
- IP rate limiting
- Session binding
- API keys with scopes
- Audit logging

### Enhanced (Recommended)
- All Standard features
- WebAuthn hardware token support
- IP allowlist/blocklist
- Geolocation blocking
- Threat intelligence
- Tamper-evident logs

### Maximum (Paranoid)
- All Enhanced features
- Client certificate authentication
- mTLS required
- VPN/proxy blocking
- Maximum rate limiting
- Shortest session TTL

## Usage Examples

### Starting the Secure Relay Server

```bash
# Using default configuration
secure-relay

# With custom config file
secure-relay --config /etc/gptl/relay.toml

# Environment variable overrides
GPTL_SECURITY_LEVEL=maximum GPTL_MFA_REQUIRED=true secure-relay
```

### API Key Management

```rust
use gptl_relay::api_key::{ApiKeyManager, ApiKeyScope};

let manager = ApiKeyManager::new();

// Create a new API key
let credentials = manager.create_key(
    "user123",
    "Production API Key",
    vec![ApiKeyScope::ReadOnly, ApiKeyScope::Relay],
    None, // Use default TTL
    None, // No custom metadata
).await?;

// Validate an API key
let validation = manager.validate_key(&credentials.full_key).await?;
```

### Session Management

```rust
use gptl_relay::session::SessionManager;

let manager = SessionManager::new(&signing_key)
    .with_access_ttl(15)
    .with_refresh_ttl(7);

// Create session
let tokens = manager.create_session(
    "user123",
    client_ip,
    Some(device_fingerprint),
    SessionMetadata::default(),
).await?;

// Validate token
let claims = manager.validate_access_token(
    &tokens.access_token,
    client_ip,
    Some(&device_fingerprint),
).await?;
```

### Audit Logging

```rust
use gptl_relay::audit::{AuditLogger, AuthEvent};

let logger = AuditLogger::new(signing_key);

// Log authentication attempt
let event = AuthEvent {
    user_id: Some("user123".to_string()),
    username: Some("alice".to_string()),
    auth_method: "password+totp".to_string(),
    success: true,
    failure_reason: None,
    mfa_used: true,
    client_cert: false,
};

let entry = logger.log_auth_attempt(event, &security_context).await?;

// Verify log integrity
let report = logger.verify_integrity().await;
```

## Testing

Run the test suite:

```bash
cd GPTL/rust
cargo test -p gptl-relay
```

Run specific security module tests:

```bash
cargo test -p gptl-relay auth::
cargo test -p gptl-relay ip_restriction::
cargo test -p gptl-relay rate_limit::
```

## Security Considerations

### Password Storage
- Uses Argon2id (Password Hashing Competition winner)
- Memory-hard (64 MiB default)
- 3 iterations, 4 parallel lanes
- Constant-time verification

### Token Security
- HS256/RS256 signatures
- Short-lived access tokens
- Secure random JWT IDs
- Binding to IP and fingerprint

### Cryptographic Practices
- SHA-256 for hashing
- HMAC-SHA256 for signatures
- Constant-time comparisons
- Secure random generation

## References

- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) - FIDO2
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [Tor Project](https://www.torproject.org/) - Guard discovery protection
- [OpenSSH](https://www.openssh.com/) - Authentication patterns
