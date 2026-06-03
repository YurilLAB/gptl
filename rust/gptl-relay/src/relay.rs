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
    api_key::ApiKeyManager, audit::AuditLogger, auth::MfaAuthenticator,
    ip_restriction::IpAllowlist, rate_limit::AuthRateLimiter, session::SessionManager,
    SecurityContext,
};
use gptl_transport::relay_node::RelayNode;

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
    /// Backing relay node — handles the actual GPTL relay protocol once
    /// the security layers above have approved an inbound connection.
    /// Configured via [`with_relay_node`].  When `None`, accepted
    /// connections still pass the IP / rate-limit checks and emit an
    /// audit event but the TCP stream is dropped (the legacy "log-only"
    /// behavior, retained for use cases that only want the audit layer).
    relay_node: Option<Arc<RelayNode>>,
    /// Server state
    state: Arc<RwLock<ServerState>>,
}

impl RelayServer {
    /// Create a new relay server.
    ///
    /// The session-token signing key is generated randomly per instance. A
    /// fixed/known key would let anyone forge valid session tokens, so there is
    /// deliberately no insecure default. To pin a key (e.g. to keep sessions
    /// valid across restarts) use [`RelayServer::with_session_manager`].
    pub fn new(config: RelayConfig) -> Self {
        let mut signing_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut signing_key);
        Self {
            config,
            auth: Arc::new(RwLock::new(MfaAuthenticator::new(
                crate::auth::PasswordHasher::default(),
                crate::auth::TotpManager::default(),
            ))),
            ip_allowlist: Arc::new(RwLock::new(IpAllowlist::default())),
            rate_limiter: Arc::new(RwLock::new(AuthRateLimiter::default())),
            session_manager: Arc::new(RwLock::new(SessionManager::new(&signing_key))),
            api_key_manager: Arc::new(RwLock::new(ApiKeyManager::default())),
            audit_logger: Arc::new(RwLock::new(AuditLogger::default())),
            relay_node: None,
            state: Arc::new(RwLock::new(ServerState::Stopped)),
        }
    }

    /// Plug in the GPTL relay-protocol handler.  Once set, accepted
    /// connections that pass the security gates are handed off to
    /// `RelayNode::handle_connection` so the secure relay actually
    /// carries circuits instead of just logging connections.
    pub fn with_relay_node(mut self, node: Arc<RelayNode>) -> Self {
        self.relay_node = Some(node);
        self
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
        let addr: SocketAddr =
            self.config.bind_address.parse().map_err(|e| {
                crate::RelayError::ConfigError(format!("Invalid bind address: {}", e))
            })?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| crate::RelayError::Internal(format!("Failed to bind: {}", e)))?;

        // Set state to running
        {
            let mut state = self.state.write().await;
            *state = ServerState::Running;
        }

        tracing::info!("Relay server listening on {}", addr);

        // Accept connections
        loop {
            let (stream, peer_addr) = listener.accept().await.map_err(|e| {
                crate::RelayError::Internal(format!("Failed to accept connection: {}", e))
            })?;

            // Handle connection in a new task
            let server = self.clone_ref();
            tokio::spawn(async move {
                if let Err(e) = server.handle_connection(stream, peer_addr).await {
                    tracing::warn!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Handle a client connection.
    ///
    /// Pipeline (each step short-circuits with an audit event on failure):
    ///   1. IP allowlist / blocklist / CIDR rule check
    ///   2. Per-IP rate-limit consume
    ///   3. Audit-log the accepted connection
    ///   4. Hand the TCP stream off to the configured `RelayNode` which
    ///      runs the actual GPTL relay protocol (handshake → circuit).
    ///      When no relay node is configured, the stream is closed at
    ///      step 3 (the legacy "log-only" mode).
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

        let ctx = SecurityContext::new(client_ip);

        // 3. Audit log the acceptance (BEFORE handing off to the relay
        //    node, so we still have a record if the protocol layer
        //    panics or hangs).
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

        // 4. Hand off to the relay protocol.
        if let Some(ref node) = self.relay_node {
            // Errors here are protocol/I/O level — log at warn, don't
            // surface as a `RelayError` (the security pipeline succeeded;
            // this is downstream).
            if let Err(e) = node.handle_connection(stream, peer_addr).await {
                tracing::warn!("relay protocol from {} ended with: {}", peer_addr, e);
            }
        } else {
            tracing::debug!(
                "no relay_node configured; dropping accepted connection from {}",
                peer_addr
            );
            drop(stream);
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
        let ctx =
            SecurityContext::new(client_ip).with_fingerprint(fingerprint.as_deref().unwrap_or(""));

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
                        "TOTP required".to_string(),
                    ));
                }
                Ok(crate::auth::AuthStep::WebAuthnChallenge { .. }) => {
                    return Err(crate::RelayError::AuthenticationFailed(
                        "WebAuthn required".to_string(),
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
            manager
                .create_session(
                    &user_id,
                    client_ip,
                    fingerprint,
                    crate::session::SessionMetadata::default(),
                )
                .await?
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
            logger
                .log_auth_attempt(event, &ctx.with_user(&user_id))
                .await?;
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
            logger
                .log_security_event(event, &ctx.with_api_key(&validation.key_id))
                .await?;
        }

        Ok(validation)
    }

    /// Get server status
    pub async fn status(&self) -> ServerStatus {
        let state = self.state.read().await;

        ServerStatus {
            state: *state,
            uptime: None,   // Would track actual uptime
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
            relay_node: self.relay_node.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use gptl_transport::cell::{Cell, CellType, RelayCell, RelayCommand};
    use gptl_transport::handshake::RelayStaticKey;
    use gptl_transport::handshake::{client_finish, client_initiate};
    use gptl_transport::relay_conn::RelayConn;
    use gptl_transport::relay_node::RelayOptions;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdTcpListener;
    use std::time::Duration;

    /// Full pipeline test: TCP accept → IP allowlist → rate-limit →
    /// audit-log → relay protocol → echo destination → round-trip.
    /// Before the wiring fix in this commit, the connection died at the
    /// "drop(stream)" step in `handle_connection` and never reached any
    /// relay logic.
    #[tokio::test]
    async fn test_secure_relay_actually_carries_circuits_after_security_pipeline() {
        // Set up an echo destination the relay will exit to.
        let echo = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in echo.incoming() {
                if let Ok(mut s) = s {
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        loop {
                            match s.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if s.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });

        // Build the secure relay with the protocol handler wired in.
        let bind = "127.0.0.1:0";
        let listener = tokio::net::TcpListener::bind(bind).await.unwrap();
        let relay_addr = listener.local_addr().unwrap();

        let static_key = RelayStaticKey::generate();
        let static_pub = static_key.public;
        let relay_node = Arc::new(RelayNode::new(
            static_key,
            RelayOptions::default().with_allow_private(true),
        ));

        let server = Arc::new(
            RelayServer::new(RelayConfig {
                bind_address: relay_addr.to_string(),
                ..RelayConfig::default()
            })
            .with_relay_node(relay_node),
        );

        // Run the accept loop manually so we don't have to expose
        // RelayServer::run with a custom listener.  We replicate the
        // accept-and-spawn pattern from `start()`.
        let server_for_accept = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let s = Arc::clone(&server_for_accept);
                tokio::spawn(async move {
                    let _ = s.handle_connection(stream, peer).await;
                });
            }
        });

        // Drive a full circuit handshake + RELAY_BEGIN + RELAY_DATA + echo.
        let mut conn = RelayConn::connect(relay_addr).await.unwrap();
        let circuit_id = 0xA5A5_A5A5u32 | 1;
        let (create, pending) = client_initiate(circuit_id, &static_pub).unwrap();
        conn.send(&create).await.unwrap();
        let created = tokio::time::timeout(Duration::from_secs(5), conn.recv())
            .await
            .expect("CREATED must arrive within 5s")
            .unwrap();
        let session = client_finish(pending, &created).unwrap();
        let mut ciphers = gptl_transport::crypto::CircuitCiphers::new(
            &session.forward_key,
            &session.backward_key,
        );

        // RELAY_BEGIN to the echo server.
        let begin = RelayCell {
            command: RelayCommand::Begin,
            stream_id: 1,
            data: format!("127.0.0.1:{}", echo_addr.port()).into_bytes(),
        };
        let pt = begin.encode().unwrap();
        let ct = ciphers.outbound.encrypt(&pt).unwrap();
        let mut cell = Cell::new(circuit_id, CellType::Relay);
        cell.payload.copy_from_slice(&ct);
        conn.send(&cell).await.unwrap();

        // Round-trip a payload.
        let mut got_connected = false;
        let mut echoed = Vec::new();
        for _ in 0..10 {
            let resp = conn.recv().await.unwrap();
            if !matches!(resp.cell_type, CellType::Relay) {
                continue;
            }
            let pt = ciphers.inbound.decrypt(&resp.payload).unwrap();
            let inner = RelayCell::decode(&pt).unwrap();
            match inner.command {
                RelayCommand::Connected => {
                    got_connected = true;
                    let data = RelayCell {
                        command: RelayCommand::Data,
                        stream_id: 1,
                        data: b"secure-relay-roundtrip".to_vec(),
                    };
                    let pt = data.encode().unwrap();
                    let ct = ciphers.outbound.encrypt(&pt).unwrap();
                    let mut cell = Cell::new(circuit_id, CellType::Relay);
                    cell.payload.copy_from_slice(&ct);
                    conn.send(&cell).await.unwrap();
                }
                RelayCommand::Data if inner.stream_id == 1 => {
                    echoed.extend_from_slice(&inner.data);
                    if echoed.len() >= 22 {
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(got_connected, "secure-relay must complete RELAY_BEGIN");
        assert_eq!(
            &echoed[..],
            b"secure-relay-roundtrip",
            "secure-relay must round-trip data through the configured RelayNode"
        );
    }
}
