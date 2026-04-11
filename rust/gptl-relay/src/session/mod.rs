//! Session Management
//!
//! Implements secure session handling inspired by enterprise systems:
//! - Short-lived JWT tokens (configurable TTL, default 15 minutes)
//! - Session binding to IP address and device fingerprint
//! - Automatic expiration and rotation
//! - Sliding window refresh tokens

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Session manager for creating and validating sessions
pub struct SessionManager {
    /// JWT encoding key
    encoding_key: EncodingKey,
    /// JWT decoding key
    decoding_key: DecodingKey,
    /// Access token TTL
    access_token_ttl: Duration,
    /// Refresh token TTL
    refresh_token_ttl: Duration,
    /// Active sessions (session_id -> Session)
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    /// Session binding enforcement
    enforce_binding: bool,
    /// Issuer claim
    issuer: String,
    /// Audience claim
    audience: String,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("enforce_binding", &self.enforce_binding)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("encoding_key", &"[REDACTED]")
            .field("decoding_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(7),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            enforce_binding: true,
            issuer: "gptl-relay".to_string(),
            audience: "gptl-client".to_string(),
        }
    }

    /// Set access token TTL
    pub fn with_access_ttl(mut self, minutes: i64) -> Self {
        self.access_token_ttl = Duration::minutes(minutes);
        self
    }

    /// Set refresh token TTL
    pub fn with_refresh_ttl(mut self, days: i64) -> Self {
        self.refresh_token_ttl = Duration::days(days);
        self
    }

    /// Disable session binding
    pub fn without_binding(mut self) -> Self {
        self.enforce_binding = false;
        self
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user_id: &str,
        client_ip: IpAddr,
        fingerprint: Option<String>,
        metadata: SessionMetadata,
    ) -> crate::Result<SessionTokens> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + self.refresh_token_ttl,
            last_activity: now,
            client_ip,
            fingerprint: fingerprint.clone(),
            metadata: metadata.clone(),
            revoked: false,
        };

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        // Generate tokens
        let access_token = self.generate_access_token(
            &session_id,
            user_id,
            &client_ip,
            fingerprint.as_deref(),
        )?;

        let refresh_token = self.generate_refresh_token(&session_id, user_id)?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl.num_seconds() as u64,
            session_id,
        })
    }

    /// Validate an access token
    pub async fn validate_access_token(
        &self,
        token: &str,
        client_ip: IpAddr,
        fingerprint: Option<&str>,
    ) -> crate::Result<TokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &validation)
            .map_err(|e| crate::RelayError::InvalidSession)?;

        let claims = token_data.claims;

        // Check session exists and is valid
        {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&claims.sid)
                .ok_or(crate::RelayError::InvalidSession)?;

            if session.revoked {
                return Err(crate::RelayError::InvalidSession);
            }

            if session.expires_at < Utc::now() {
                return Err(crate::RelayError::InvalidSession);
            }
        }

        // Verify session binding if enforced
        if self.enforce_binding {
            // Check IP binding
            if claims.ip != client_ip.to_string() {
                return Err(crate::RelayError::SessionBindingMismatch(
                    "IP address mismatch".to_string()
                ));
            }

            // Check fingerprint binding
            if let (Some(expected_fp), Some(provided_fp)) = (&claims.fp, fingerprint) {
                if expected_fp != provided_fp {
                    return Err(crate::RelayError::SessionBindingMismatch(
                        "Device fingerprint mismatch".to_string()
                    ));
                }
            }
        }

        Ok(claims)
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        client_ip: IpAddr,
        fingerprint: Option<String>,
    ) -> crate::Result<SessionTokens> {
        // Validate refresh token
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<RefreshClaims>(refresh_token, &self.decoding_key, &validation)
            .map_err(|e| crate::RelayError::InvalidSession)?;

        let claims = token_data.claims;

        // Check token type
        if claims.typ != "refresh" {
            return Err(crate::RelayError::InvalidSession);
        }

        // Get session
        let mut session = {
            let sessions = self.sessions.read().await;
            sessions.get(&claims.sid)
                .cloned()
                .ok_or(crate::RelayError::InvalidSession)?
        };

        // Check session validity
        if session.revoked || session.expires_at < Utc::now() {
            return Err(crate::RelayError::InvalidSession);
        }

        // Update session
        session.last_activity = Utc::now();
        session.client_ip = client_ip;
        if let Some(ref fp) = fingerprint {
            session.fingerprint = Some(fp.clone());
        }

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(claims.sid.clone(), session.clone());
        }

        // Generate new tokens
        let access_token = self.generate_access_token(
            &claims.sid,
            &session.user_id,
            &client_ip,
            fingerprint.as_deref(),
        )?;

        let new_refresh_token = self.generate_refresh_token(&claims.sid, &session.user_id)?;

        Ok(SessionTokens {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.access_token_ttl.num_seconds() as u64,
            session_id: claims.sid,
        })
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: &str) -> crate::Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            session.revoked = true;
            Ok(())
        } else {
            Err(crate::RelayError::InvalidSession)
        }
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all_user_sessions(&self, user_id: &str) -> crate::Result<u64> {
        let mut sessions = self.sessions.write().await;
        let mut revoked_count = 0;

        for (_, session) in sessions.iter_mut() {
            if session.user_id == user_id && !session.revoked {
                session.revoked = true;
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }

    /// Get session information
    pub async fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        
        sessions.get(session_id).map(|s| SessionInfo {
            id: s.id.clone(),
            user_id: s.user_id.clone(),
            created_at: s.created_at,
            expires_at: s.expires_at,
            last_activity: s.last_activity,
            client_ip: s.client_ip,
            fingerprint: s.fingerprint.clone(),
            revoked: s.revoked,
        })
    }

    /// List active sessions for a user
    pub async fn list_user_sessions(&self, user_id: &str) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        
        sessions.values()
            .filter(|s| s.user_id == user_id && !s.revoked && s.expires_at > Utc::now())
            .map(|s| SessionInfo {
                id: s.id.clone(),
                user_id: s.user_id.clone(),
                created_at: s.created_at,
                expires_at: s.expires_at,
                last_activity: s.last_activity,
                client_ip: s.client_ip,
                fingerprint: s.fingerprint.clone(),
                revoked: s.revoked,
            })
            .collect()
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        sessions.retain(|_, s| s.expires_at > now && !s.revoked);
    }

    /// Generate access token
    fn generate_access_token(
        &self,
        session_id: &str,
        user_id: &str,
        client_ip: &IpAddr,
        fingerprint: Option<&str>,
    ) -> crate::Result<String> {
        let now = Utc::now();
        let claims = TokenClaims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now.timestamp(),
            exp: (now + self.access_token_ttl).timestamp(),
            nbf: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            typ: "access".to_string(),
            ip: client_ip.to_string(),
            fp: fingerprint.map(|s| s.to_string()),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| crate::RelayError::Internal(
                format!("Token generation failed: {}", e)
            ))
    }

    /// Generate refresh token
    fn generate_refresh_token(&self, session_id: &str, user_id: &str) -> crate::Result<String> {
        let now = Utc::now();
        let claims = RefreshClaims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now.timestamp(),
            exp: (now + self.refresh_token_ttl).timestamp(),
            typ: "refresh".to_string(),
        };

        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|e| crate::RelayError::Internal(
                format!("Token generation failed: {}", e)
            ))
    }
}

/// JWT token claims for access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Session ID
    pub sid: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Issued at
    pub iat: i64,
    /// Expiration
    pub exp: i64,
    /// Not valid before
    pub nbf: i64,
    /// JWT ID
    pub jti: String,
    /// Token type
    pub typ: String,
    /// IP address binding
    pub ip: String,
    /// Fingerprint binding
    pub fp: Option<String>,
}

/// JWT claims for refresh tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Session ID
    pub sid: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Issued at
    pub iat: i64,
    /// Expiration
    pub exp: i64,
    /// Token type
    pub typ: String,
}

/// Session stored in memory
#[derive(Debug, Clone)]
struct Session {
    id: String,
    user_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    client_ip: IpAddr,
    fingerprint: Option<String>,
    metadata: SessionMetadata,
    revoked: bool,
}

/// Session metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub user_agent: Option<String>,
    pub device_type: Option<String>,
    pub os: Option<String>,
    pub browser: Option<String>,
}

/// Session tokens returned to client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub session_id: String,
}

/// Session information for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub client_ip: IpAddr,
    pub fingerprint: Option<String>,
    pub revoked: bool,
}

/// Session binding information
#[derive(Debug, Clone)]
pub struct SessionBinding {
    pub ip_address: IpAddr,
    pub fingerprint: Option<String>,
}

impl SessionBinding {
    /// Create a new session binding
    pub fn new(ip_address: IpAddr, fingerprint: Option<String>) -> Self {
        Self {
            ip_address,
            fingerprint,
        }
    }

    /// Check if request matches binding
    pub fn matches(&self, ip: IpAddr, fingerprint: Option<&str>) -> bool {
        self.ip_address == ip && self.fingerprint.as_deref() == fingerprint
    }
}

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let manager = SessionManager::new(b"test_secret_key_for_testing_purposes");
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        let tokens = manager.create_session(
            "user123",
            ip,
            Some("device_fingerprint".to_string()),
            SessionMetadata::default(),
        ).await.unwrap();
        
        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");
        assert!(!tokens.session_id.is_empty());
    }

    #[tokio::test]
    async fn test_token_validation() {
        let manager = SessionManager::new(b"test_secret_key_for_testing_purposes");
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        let tokens = manager.create_session(
            "user123",
            ip,
            Some("device_fingerprint".to_string()),
            SessionMetadata::default(),
        ).await.unwrap();
        
        // Valid validation
        let claims = manager.validate_access_token(
            &tokens.access_token,
            ip,
            Some("device_fingerprint"),
        ).await.unwrap();
        
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.typ, "access");
        
        // Wrong IP should fail
        let wrong_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = manager.validate_access_token(
            &tokens.access_token,
            wrong_ip,
            Some("device_fingerprint"),
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_session_revocation() {
        let manager = SessionManager::new(b"test_secret_key_for_testing_purposes");
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        let tokens = manager.create_session(
            "user123",
            ip,
            None,
            SessionMetadata::default(),
        ).await.unwrap();
        
        // Revoke session
        manager.revoke_session(&tokens.session_id).await.unwrap();
        
        // Token should be invalid now
        let result = manager.validate_access_token(&tokens.access_token, ip, None).await;
        assert!(result.is_err());
    }
}
