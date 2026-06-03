//! Multi-Factor Authentication Module
//!
//! Implements layered authentication inspired by SSH and enterprise systems:
//! - Knowledge factor: Password (Argon2id)
//! - Possession factor: TOTP (RFC 6238) or hardware tokens (FIDO2/WebAuthn)
//! - Inherence factor: Client certificates (mTLS)

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod client_cert;
pub mod password;
pub mod totp;
pub mod webauthn;

pub use client_cert::ClientCertVerifier;
pub use password::PasswordHasher;
pub use totp::TotpManager;
pub use webauthn::WebAuthnManager;

#[cfg(feature = "webauthn")]
pub use webauthn::{
    AuthChallenge, AuthenticationResult, CredentialInfo, RegistrationChallenge, RegistrationResult,
};

/// Multi-factor authentication manager
#[derive(Debug)]
pub struct MfaAuthenticator {
    /// Password hasher for knowledge factor
    password_hasher: PasswordHasher,
    /// TOTP manager for time-based codes
    totp_manager: TotpManager,
    /// WebAuthn manager for hardware tokens
    webauthn_manager: Option<WebAuthnManager>,
    /// Client certificate verifier
    cert_verifier: Option<ClientCertVerifier>,
    /// User MFA configurations
    user_configs: Arc<RwLock<HashMap<String, MfaConfig>>>,
    /// Pending authentication attempts
    pending_auths: Arc<RwLock<HashMap<String, PendingAuth>>>,
}

impl MfaAuthenticator {
    /// Create a new MFA authenticator
    pub fn new(password_hasher: PasswordHasher, totp_manager: TotpManager) -> Self {
        Self {
            password_hasher,
            totp_manager,
            webauthn_manager: None,
            cert_verifier: None,
            user_configs: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Enable WebAuthn hardware token support
    pub fn with_webauthn(mut self, manager: WebAuthnManager) -> Self {
        self.webauthn_manager = Some(manager);
        self
    }

    /// Enable client certificate authentication
    pub fn with_client_certs(mut self, verifier: ClientCertVerifier) -> Self {
        self.cert_verifier = Some(verifier);
        self
    }

    /// Configure MFA for a user
    pub async fn configure_user(&self, user_id: &str, config: MfaConfig) -> crate::Result<()> {
        let mut configs = self.user_configs.write().await;
        configs.insert(user_id.to_string(), config);
        Ok(())
    }

    /// Start authentication process (Step 1: Verify password)
    pub async fn start_authentication(
        &self,
        username: &str,
        password: &str,
    ) -> crate::Result<AuthStep> {
        // Verify password first
        let configs = self.user_configs.read().await;
        let config = configs
            .get(username)
            .ok_or_else(|| crate::RelayError::AuthenticationFailed("User not found".to_string()))?;

        if !self
            .password_hasher
            .verify(password, &config.password_hash)?
        {
            return Err(crate::RelayError::AuthenticationFailed(
                "Invalid password".to_string(),
            ));
        }

        // Password verified, determine next step
        let pending = PendingAuth {
            user_id: username.to_string(),
            password_verified: true,
            step: 1,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
        };

        let auth_id = uuid::Uuid::new_v4().to_string();
        let next_step = if config.totp_enabled {
            AuthStep::TotpRequired {
                auth_id: auth_id.clone(),
            }
        } else if config.webauthn_enabled && self.webauthn_manager.is_some() {
            AuthStep::WebAuthnChallenge {
                auth_id: auth_id.clone(),
            }
        } else {
            AuthStep::Complete {
                user_id: username.to_string(),
            }
        };

        let mut pending_auths = self.pending_auths.write().await;
        pending_auths.insert(auth_id, pending);

        Ok(next_step)
    }

    /// Continue authentication with TOTP (Step 2)
    pub async fn verify_totp(&self, auth_id: &str, code: &str) -> crate::Result<AuthStep> {
        let mut pending_auths = self.pending_auths.write().await;

        let pending = pending_auths.get(auth_id).ok_or_else(|| {
            crate::RelayError::AuthenticationFailed(
                "Invalid or expired authentication session".to_string(),
            )
        })?;

        if pending.expires_at < Utc::now() {
            pending_auths.remove(auth_id);
            return Err(crate::RelayError::AuthenticationFailed(
                "Authentication session expired".to_string(),
            ));
        }

        let configs = self.user_configs.read().await;
        let config = configs.get(&pending.user_id).ok_or_else(|| {
            crate::RelayError::AuthenticationFailed("User configuration not found".to_string())
        })?;

        // Verify TOTP code
        if !self.totp_manager.verify(&config.totp_secret, code)? {
            return Err(crate::RelayError::AuthenticationFailed(
                "Invalid TOTP code".to_string(),
            ));
        }

        // Check if WebAuthn is also required
        let next_step = if config.webauthn_enabled && self.webauthn_manager.is_some() {
            AuthStep::WebAuthnChallenge {
                auth_id: auth_id.to_string(),
            }
        } else {
            let user_id = pending.user_id.clone();
            pending_auths.remove(auth_id);
            AuthStep::Complete { user_id }
        };

        Ok(next_step)
    }

    /// Authenticate with client certificate directly
    pub async fn authenticate_with_certificate(
        &self,
        certificate: &client_cert::ClientCertificate,
    ) -> crate::Result<String> {
        let verifier = self.cert_verifier.as_ref().ok_or_else(|| {
            crate::RelayError::AuthenticationFailed(
                "Client certificate authentication not configured".to_string(),
            )
        })?;

        verifier.verify_certificate(certificate).await
    }

    /// Cleanup expired pending authentications
    pub async fn cleanup_expired(&self) {
        let mut pending_auths = self.pending_auths.write().await;
        let now = Utc::now();
        pending_auths.retain(|_, auth| auth.expires_at > now);
    }
}

/// MFA configuration for a user
#[derive(Debug, Clone)]
pub struct MfaConfig {
    /// Argon2id password hash
    pub password_hash: String,
    /// Whether TOTP is enabled
    pub totp_enabled: bool,
    /// TOTP secret (encrypted at rest)
    pub totp_secret: String,
    /// Whether WebAuthn is enabled
    pub webauthn_enabled: bool,
    /// Registered WebAuthn credential IDs
    pub webauthn_credentials: Vec<String>,
    /// Whether client certificate is required
    pub client_cert_required: bool,
    /// Allowed client certificate fingerprints
    pub allowed_client_certs: Vec<String>,
}

/// Pending authentication state
#[derive(Debug, Clone)]
struct PendingAuth {
    user_id: String,
    password_verified: bool,
    step: u8,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// Authentication step result
#[derive(Debug, Clone)]
pub enum AuthStep {
    /// TOTP code required
    TotpRequired { auth_id: String },
    /// WebAuthn challenge required
    WebAuthnChallenge { auth_id: String },
    /// Authentication complete
    Complete { user_id: String },
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Password only (not recommended)
    Password,
    /// Password + TOTP
    PasswordTotp,
    /// Password + WebAuthn
    PasswordWebAuthn,
    /// Password + TOTP + WebAuthn (maximum security)
    PasswordTotpWebAuthn,
    /// Client certificate only
    ClientCertificate,
    /// Client certificate + TOTP
    ClientCertificateTotp,
}

impl AuthMethod {
    /// Get the number of factors
    pub fn factor_count(&self) -> u8 {
        match self {
            AuthMethod::Password => 1,
            AuthMethod::PasswordTotp => 2,
            AuthMethod::PasswordWebAuthn => 2,
            AuthMethod::PasswordTotpWebAuthn => 3,
            AuthMethod::ClientCertificate => 1,
            AuthMethod::ClientCertificateTotp => 2,
        }
    }

    /// Check if this method satisfies MFA requirements
    pub fn is_mfa(&self) -> bool {
        self.factor_count() >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_factors() {
        assert_eq!(AuthMethod::Password.factor_count(), 1);
        assert_eq!(AuthMethod::PasswordTotp.factor_count(), 2);
        assert_eq!(AuthMethod::PasswordTotpWebAuthn.factor_count(), 3);

        assert!(!AuthMethod::Password.is_mfa());
        assert!(AuthMethod::PasswordTotp.is_mfa());
        assert!(AuthMethod::PasswordWebAuthn.is_mfa());
    }
}
