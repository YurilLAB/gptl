//! Main Relay Server with Multi-Layer Security
//!
//! The secure relay server integrating all authentication and access control layers:
//! - Multi-factor authentication
//! - IP-based restrictions
//! - Rate limiting
//! - Session management
//! - API key system
//! - Audit logging

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::{
    auth::MfaAuthenticator,
    ip_restriction::IpAllowlist,
    rate_limit::AuthRateLimiter,
    session::SessionManager,
    api_key::ApiKeyManager,
    audit::AuditLogger,
    SecurityContext,
};

/// Secure relay server
#[derive(Debug)]
pub struct RelayServer {
    /// Server configuration
    config: RelayConfig,
    /// Multi-factor authenticator
    auth: Arc<RwLock<MfaAuthenticator>>,
    /// IP allowlist/blocklist
    ip_allowlist: Arc<RwLock<IpAllowlist>>,
    /// Rate limiter
    rate_limiter: Arc<RwLock<AuthRateLimiter>>,
    /// Session manager
    session_manager: Arc<RwLock<SessionManager>>,
    /// API key manager
    api_key_manager: Arc<RwLock<ApiKeyManager>>,
    /// Audit logger
    audit_logger: Arc<RwLock<AuditLogger>>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
}

impl RelayServer {
    /// Create a new relay server
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            auth: Arc::new(RwLock::new(MfaAuthenticator::new(
                crate::auth::PasswordHasher::default(),
                crate::auth::TotpManager::default(),
            ))),
            ip_allowlist: Arc::new(RwLock::new(IpAllowlist::default())),
            rate_limiter: Arc::new(RwLock::new(AuthRateLimiter::default())),
            session_manager: Arc::new(RwLock::new(SessionManager::new(&[0u8; 32]))),
            api_key_manager: Arc::new(RwLock::new(ApiKeyManager::default())),
            audit_logger: Arc::new(RwLock::new(AuditLogger::default())),
            state: Arc::new(RwLock::new(ServerState::Stopped)),
        }
    }

    /// Configure MFA authenticator
    pub fn with_auth(mut self, auth: MfaAuthenticator) -> Self {
        self.auth = Arc::new(RwLock::new(auth));
        self
    }

    /// Configure IP allowlist
    pub fn with_ip_allowlist(mut self, allowlist: IpAllowlist) -> Self {
        self.ip_allowlist = Arc::new(RwLock::new(allowlist));
        self
    }

    /// Configure rate limiter
    pub fn with_rate_limiter(mut self, limiter: AuthRateLimiter) -> Self {
        self.rate_limiter = Arc::new(RwLock::new(limiter));
        self
    }

    /// Configure session manager
    pub fn with_session_manager(mut self, manager: SessionManager) -> Self {
        self.session_manager = Arc::new(RwLock::new(manager));
        self
    }

    /// Configure API key manager
    pub fn with_api_key_manager(mut self, manager: ApiKeyManager) -> Self {
        self.api_key_manager = Arc::new(RwLock::new(manager));
        self
    }

    /// Configure audit logger
    pub fn with_audit_logger(mut self, logger: AuditLogger) -> Self {
        self.audit_logger = Arc::new(RwLock::new(logger));
        self
    }

    /// Initialize the server
    pub async fn initialize(&self) -> crate::Result<()> {
        // Initialize IP allowlist
        {
            let allowlist = self.ip_allowlist.read().await;
            // Load any configured allowlists
        }

        // Initialize audit logger
        {
            let logger = self.audit_logger.read().await;
            // Verify log integrity
            let _report = logger.verify_integrity().await;
        }

        // Set state to initialized
        let mut state = self.state.write().await;
        *state = ServerState::Initialized;

        Ok(())
    }

    /// Start the relay server
    pub async fn start(&self) -> crate::Result<()> {
        // Initialize if not already done
        self.initialize().await?;

        // Bind to address
        let addr: SocketAddr = self.config.bind_address.parse()
            .map_err(|e| crate::RelayError::ConfigError(
                format!("Invalid bind address: {}", e)
            ))?;

        let listener = TcpListener::bind(addr).await
            .map_err(|e| crate::RelayError::Internal(
                format!("Failed to bind: {}", e)
            ))?;

        // Set state to running
        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        tracing::info!("Relay server listening on {}", addr);

        // Accept connections
        loop {
            let (stream, peer_addr) = listener.accept().await
                .map_err(|e| crate::RelayError::Internal(
                    format!("Failed to accept connection: {}", e)
                ))?;

            // Handle connection in a new task
            let server = self.clone_ref();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer_addr).await {
                    tracing::warn!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Handle a client connection
    async fn handle_connection(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> crate::Result<()> {
        let client_ip = peer_addr.ip();

        // 1. IP-based restriction check
        {
            let allowlist = self.ip_allowlist.read().await;
            allowlist.is_allowed(client_ip).await?;
        }

        // 2. Rate limiting check
        {
            let limiter = self.rate_limiter.read().await;
            limiter.check_ip(client_ip).await?;
        }

        // Connection is now accepted
        // In a real implementation, this would handle the protocol
        // For now, we just log the connection

        let ctx = SecurityContext::new(client_ip);
        
        {
            let logger = self.audit_logger.read().await;
            let event = crate::audit::SecurityEventType {
                event_type: "connection_accepted".to_string(),
                severity: crate::audit::SecuritySeverity::Low,
                description: format!("Connection accepted from {}", client_ip),
                details: None,
            };
            logger.log_security_event(event, &ctx).await?;
        }

        Ok(())
    }

    /// Authenticate a user with full security checks
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        client_ip: IpAddr,
        fingerprint: Option<String>,
    ) -> crate::Result<crate::session::SessionTokens> {
        let ctx = SecurityContext::new(client_ip)
            .with_fingerprint(fingerprint.as_deref().unwrap_or(""));

        // 1. IP check
        {
            let allowlist = self.ip_allowlist.read().await;
            allowlist.is_allowed(client_ip).await?;
        }

        // 2. Rate limiting
        {
            let limiter = self.rate_limiter.read().await;
            limiter.check_ip(client_ip).await?;
            limiter.check_account(username).await?;
        }

        // 3. MFA Authentication
        let user_id = {
            let auth = self.auth.read().await;
            let result = auth.start_authentication(username, password).await;
            
            // Handle the result
            match result {
                Ok(crate::auth::AuthStep::Complete { user_id }) => user_id,
                Ok(crate::auth::AuthStep::TotpRequired { .. }) => {
                    return Err(crate::RelayError::AuthenticationFailed(
                        "TOTP required".to_string()
                    ));
                }
                Ok(crate::auth::AuthStep::WebAuthnChallenge { .. }) => {
                    return Err(crate::RelayError::AuthenticationFailed(
                        "WebAuthn required".to_string()
                    ));
                }
                Err(e) => {
                    // Record failure for rate limiting
                    let limiter = self.rate_limiter.read().await;
                    limiter.record_failure(client_ip, username).await;
                    return Err(e);
                }
            }
        };

        // 4. Record success
        {
            let limiter = self.rate_limiter.read().await;
            limiter.record_success(client_ip, username).await;
        }

        // 5. Create session
        let tokens = {
            let manager = self.session_manager.read().await;
            manager.create_session(
                &user_id,
                client_ip,
                fingerprint,
                crate::session::SessionMetadata::default(),
            ).await?
        };

        // 6. Log authentication success
        {
            let logger = self.audit_logger.read().await;
            let event = crate::audit::AuthEvent {
                user_id: Some(user_id.clone()),
                username: Some(username.to_string()),
                auth_method: "password".to_string(),
                success: true,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx.with_user(&user_id)).await?;
        }

        Ok(tokens)
    }

    /// Authenticate with API key
    pub async fn authenticate_api_key(
        &self,
        api_key: &str,
        client_ip: IpAddr,
    ) -> crate::Result<crate::api_key::ApiKeyValidation> {
        let ctx = SecurityContext::new(client_ip);

        // 1. IP check
        {
            let allowlist = self.ip_allowlist.read().await;
            allowlist.is_allowed(client_ip).await?;
        }

        // 2. Validate API key
        let validation = {
            let manager = self.api_key_manager.read().await;
            manager.validate_key(api_key).await?
        };

        // 3. Log API key usage
        {
            let logger = self.audit_logger.read().await;
            let event = crate::audit::SecurityEventType {
                event_type: "api_key_auth".to_string(),
                severity: crate::audit::SecuritySeverity::Low,
                description: format!("API key authentication for {}", validation.user_id),
                details: Some(serde_json::json!({
                    "key_id": validation.key_id,
                    "scopes": validation.scopes,
                })),
            };
            logger.log_security_event(event, &ctx.with_api_key(&validation.key_id)).await?;
        }

        Ok(validation)
    }

    /// Get server status
    pub async fn status(&self) -> ServerStatus {
        let state = self.state.read().await;
        
        ServerStatus {
            state: *state,
            uptime: None, // Would track actual uptime
            connections: 0, // Would track active connections
        }
    }

    /// Shutdown the server
    pub async fn shutdown(&self) -> crate::Result<()> {
        let mut state = self.state.write().await;
        *state = ServerState::Stopping;

        // Cleanup operations
        
        *state = ServerState::Stopped;
        Ok(())
    }

    /// Clone internal references for use in spawned tasks
    fn clone_ref(&self) -> Self {
        Self {
            config: self.config.clone(),
            auth: self.auth.clone(),
            ip_allowlist: self.ip_allowlist.clone(),
            rate_limiter: self.rate_limiter.clone(),
            session_manager: self.session_manager.clone(),
            api_key_manager: self.api_key_manager.clone(),
            audit_logger: self.audit_logger.clone(),
            state: self.state.clone(),
        }
    }
}

/// Relay server configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Bind address
    pub bind_address: String,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Enable mTLS
    pub mtls_enabled: bool,
    /// mTLS CA certificate path
    pub mtls_ca_path: Option<String>,
    /// Request timeout
    pub request_timeout_secs: u64,
    /// Maximum connections
    pub max_connections: usize,
    /// Enable all security features
    pub strict_mode: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:8443".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            mtls_enabled: false,
            mtls_ca_path: None,
            request_timeout_secs: 30,
            max_connections: 1000,
            strict_mode: true,
        }
    }
}

/// Server state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerState {
    Stopped,
    Initializing,
    Initialized,
    Running,
    Stopping,
    Error,
}

/// Server status
#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub state: ServerState,
    pub uptime: Option<std::time::Duration>,
    pub connections: usize,
}
