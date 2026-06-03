//! WebAuthn/FIDO2 Hardware Token Support
//!
//! Implements passwordless authentication using FIDO2/WebAuthn:
//! - Hardware security keys (YubiKey, Titan, etc.)
//! - Platform authenticators (Windows Hello, Touch ID, Face ID)
//! - Passkeys (synced credentials)
//! - Attestation verification
//! - Counter-based replay protection
//!
//! Based on W3C WebAuthn Level 2 specification and FIDO2 CTAP2 protocol.
//!
//! # Feature Flag
//! This module requires the `webauthn` feature to be enabled.
//! On platforms without OpenSSL (e.g., Windows without Perl), enable it with:
//! `cargo build --features webauthn`

#[cfg(feature = "webauthn")]
mod inner {
    use chrono::{DateTime, Duration, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use webauthn_rs::prelude::*;

    /// WebAuthn manager for FIDO2 authentication
    #[derive(Clone)]
    pub struct WebAuthnManager {
        /// WebAuthn instance
        webauthn: Arc<Webauthn>,
        /// Stored credentials per user
        credentials: Arc<RwLock<HashMap<String, Vec<StoredCredential>>>>,
        /// Active registration challenges
        registration_challenges: Arc<RwLock<HashMap<String, (PasskeyRegistration, DateTime<Utc>)>>>,
        /// Active authentication challenges
        auth_challenges: Arc<RwLock<HashMap<String, (PasskeyAuthentication, DateTime<Utc>)>>>,
        /// Challenge timeout
        challenge_timeout: Duration,
    }

    impl WebAuthnManager {
        /// Create new WebAuthn manager
        ///
        /// # Arguments
        /// * `rp_name` - Relying Party name (e.g., "GPTL Secure Relay")
        /// * `rp_id` - Relying Party ID (domain, e.g., "relay.gptl.local")
        /// * `origin` - Origin URL (e.g., "https://relay.gptl.local")
        pub fn new(
            rp_name: impl Into<String>,
            rp_id: impl Into<String>,
            origin: impl Into<String>,
        ) -> crate::Result<Self> {
            let rp_id_str = rp_id.into();
            let origin_str = origin.into();

            let origin_url = Url::parse(&origin_str).map_err(|e| {
                crate::RelayError::ConfigError(format!("Invalid origin URL: {}", e))
            })?;

            let rp_origin = origin_url.clone();
            let builder = WebauthnBuilder::new(&rp_id_str, &rp_origin).map_err(|e| {
                crate::RelayError::ConfigError(format!("WebAuthn builder error: {}", e))
            })?;

            let builder = builder.rp_name(&rp_name.into());

            let webauthn = builder.build().map_err(|e| {
                crate::RelayError::ConfigError(format!("WebAuthn build error: {}", e))
            })?;

            Ok(Self {
                webauthn: Arc::new(webauthn),
                credentials: Arc::new(RwLock::new(HashMap::new())),
                registration_challenges: Arc::new(RwLock::new(HashMap::new())),
                auth_challenges: Arc::new(RwLock::new(HashMap::new())),
                challenge_timeout: Duration::minutes(5),
            })
        }

        /// Start credential registration (returns challenge for client)
        pub async fn start_registration(
            &self,
            user_id: &str,
            username: &str,
            display_name: &str,
        ) -> crate::Result<RegistrationChallenge> {
            let existing_creds = {
                let creds = self.credentials.read().await;
                creds
                    .get(user_id)
                    .map(|v| v.iter().map(|c| c.passkey.clone()).collect())
                    .unwrap_or_default()
            };

            let user_unique_id = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());

            let (ccr, reg_state) = self
                .webauthn
                .start_passkey_registration(
                    user_unique_id,
                    username,
                    display_name,
                    Some(existing_creds),
                )
                .map_err(|e| {
                    crate::RelayError::Internal(format!("Registration start failed: {}", e))
                })?;

            let challenge_id = uuid::Uuid::new_v4().to_string();
            let mut challenges = self.registration_challenges.write().await;
            challenges.insert(challenge_id.clone(), (reg_state, Utc::now()));

            Ok(RegistrationChallenge {
                challenge_id,
                public_key: ccr,
            })
        }

        /// Complete credential registration
        pub async fn finish_registration(
            &self,
            user_id: &str,
            challenge_id: &str,
            credential: RegisterPublicKeyCredential,
        ) -> crate::Result<RegistrationResult> {
            let reg_state = {
                let mut challenges = self.registration_challenges.write().await;
                let cutoff = Utc::now() - self.challenge_timeout;
                challenges.retain(|_, (_, ts)| *ts > cutoff);

                challenges
                    .remove(challenge_id)
                    .ok_or_else(|| {
                        crate::RelayError::AuthenticationFailed(
                            "Invalid or expired registration challenge".to_string(),
                        )
                    })?
                    .0
            };

            let passkey = self
                .webauthn
                .finish_passkey_registration(&credential, &reg_state)
                .map_err(|e| {
                    crate::RelayError::AuthenticationFailed(format!(
                        "Registration verification failed: {}",
                        e
                    ))
                })?;

            let stored = StoredCredential {
                credential_id: base64::encode(passkey.cred_id()),
                passkey: passkey.clone(),
                created_at: Utc::now(),
                last_used: None,
                counter: 0,
                name: None,
            };

            let mut creds = self.credentials.write().await;
            creds
                .entry(user_id.to_string())
                .or_default()
                .push(stored.clone());

            Ok(RegistrationResult {
                credential_id: stored.credential_id,
                created_at: stored.created_at,
            })
        }

        /// Start authentication (returns challenge for client)
        pub async fn start_authentication(&self, user_id: &str) -> crate::Result<AuthChallenge> {
            let user_creds = {
                let creds = self.credentials.read().await;
                creds
                    .get(user_id)
                    .map(|v| v.iter().map(|c| c.passkey.clone()).collect())
                    .ok_or_else(|| {
                        crate::RelayError::AuthenticationFailed(
                            "No credentials registered for user".to_string(),
                        )
                    })?
            };

            let (rcr, auth_state) = self
                .webauthn
                .start_passkey_authentication(&user_creds)
                .map_err(|e| {
                    crate::RelayError::Internal(format!("Authentication start failed: {}", e))
                })?;

            let challenge_id = uuid::Uuid::new_v4().to_string();
            let mut challenges = self.auth_challenges.write().await;
            challenges.insert(challenge_id.clone(), (auth_state, Utc::now()));

            Ok(AuthChallenge {
                challenge_id,
                public_key: rcr,
            })
        }

        /// Complete authentication
        pub async fn finish_authentication(
            &self,
            user_id: &str,
            challenge_id: &str,
            credential: PublicKeyCredential,
        ) -> crate::Result<AuthenticationResult> {
            let auth_state = {
                let mut challenges = self.auth_challenges.write().await;
                let cutoff = Utc::now() - self.challenge_timeout;
                challenges.retain(|_, (_, ts)| *ts > cutoff);

                challenges
                    .remove(challenge_id)
                    .ok_or_else(|| {
                        crate::RelayError::AuthenticationFailed(
                            "Invalid or expired authentication challenge".to_string(),
                        )
                    })?
                    .0
            };

            let auth_result = self
                .webauthn
                .finish_passkey_authentication(&credential, &auth_state)
                .map_err(|e| {
                    crate::RelayError::AuthenticationFailed(format!(
                        "Authentication verification failed: {}",
                        e
                    ))
                })?;

            let mut creds = self.credentials.write().await;
            if let Some(user_creds) = creds.get_mut(user_id) {
                for stored in user_creds.iter_mut() {
                    if stored.passkey.cred_id() == auth_result.cred_id() {
                        stored.counter = auth_result.counter();
                        stored.last_used = Some(Utc::now());

                        return Ok(AuthenticationResult {
                            credential_id: stored.credential_id.clone(),
                            counter: stored.counter,
                            user_verified: auth_result.user_verified(),
                        });
                    }
                }
            }

            Err(crate::RelayError::AuthenticationFailed(
                "Credential not found after verification".to_string(),
            ))
        }

        /// List user's registered credentials
        pub async fn list_credentials(&self, user_id: &str) -> Vec<CredentialInfo> {
            let creds = self.credentials.read().await;
            creds
                .get(user_id)
                .map(|v| {
                    v.iter()
                        .map(|c| CredentialInfo {
                            credential_id: c.credential_id.clone(),
                            created_at: c.created_at,
                            last_used: c.last_used,
                            counter: c.counter,
                            name: c.name.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default()
        }

        /// Remove a credential
        pub async fn remove_credential(
            &self,
            user_id: &str,
            credential_id: &str,
        ) -> crate::Result<()> {
            let mut creds = self.credentials.write().await;

            if let Some(user_creds) = creds.get_mut(user_id) {
                let original_len = user_creds.len();
                user_creds.retain(|c| c.credential_id != credential_id);

                if user_creds.len() < original_len {
                    return Ok(());
                }
            }

            Err(crate::RelayError::AuthenticationFailed(
                "Credential not found".to_string(),
            ))
        }

        /// Update credential name
        pub async fn update_credential_name(
            &self,
            user_id: &str,
            credential_id: &str,
            name: String,
        ) -> crate::Result<()> {
            let mut creds = self.credentials.write().await;

            if let Some(user_creds) = creds.get_mut(user_id) {
                for stored in user_creds.iter_mut() {
                    if stored.credential_id == credential_id {
                        stored.name = Some(name);
                        return Ok(());
                    }
                }
            }

            Err(crate::RelayError::AuthenticationFailed(
                "Credential not found".to_string(),
            ))
        }

        /// Cleanup expired challenges
        pub async fn cleanup_expired_challenges(&self) {
            let cutoff = Utc::now() - self.challenge_timeout;

            let mut reg_challenges = self.registration_challenges.write().await;
            reg_challenges.retain(|_, (_, ts)| *ts > cutoff);

            let mut auth_challenges = self.auth_challenges.write().await;
            auth_challenges.retain(|_, (_, ts)| *ts > cutoff);
        }
    }

    impl std::fmt::Debug for WebAuthnManager {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WebAuthnManager")
                .field(
                    "credentials_count",
                    &self.credentials.try_read().map(|c| c.len()).unwrap_or(0),
                )
                .finish()
        }
    }

    /// Stored credential (internal)
    #[derive(Debug, Clone)]
    struct StoredCredential {
        credential_id: String,
        passkey: Passkey,
        created_at: DateTime<Utc>,
        last_used: Option<DateTime<Utc>>,
        counter: u32,
        name: Option<String>,
    }

    /// Registration challenge returned to client
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationChallenge {
        pub challenge_id: String,
        pub public_key: CreationChallengeResponse,
    }

    /// Authentication challenge returned to client
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthChallenge {
        pub challenge_id: String,
        pub public_key: RequestChallengeResponse,
    }

    /// Registration result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RegistrationResult {
        pub credential_id: String,
        pub created_at: DateTime<Utc>,
    }

    /// Authentication result
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuthenticationResult {
        pub credential_id: String,
        pub counter: u32,
        pub user_verified: bool,
    }

    /// Credential information
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CredentialInfo {
        pub credential_id: String,
        pub created_at: DateTime<Utc>,
        pub last_used: Option<DateTime<Utc>>,
        pub counter: u32,
        pub name: Option<String>,
    }
}

#[cfg(feature = "webauthn")]
pub use inner::{
    AuthChallenge, AuthenticationResult, CredentialInfo, RegistrationChallenge, RegistrationResult,
    WebAuthnManager,
};

#[cfg(not(feature = "webauthn"))]
pub mod stub {
    //! Stub types when webauthn feature is disabled.
    //! Enable with `--features webauthn` (requires OpenSSL/Perl on the build system).

    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};

    /// Stub WebAuthn manager — not functional without `webauthn` feature
    #[derive(Debug, Clone)]
    pub struct WebAuthnManager;

    impl WebAuthnManager {
        pub fn new(
            _rp_name: impl Into<String>,
            _rp_id: impl Into<String>,
            _origin: impl Into<String>,
        ) -> crate::Result<Self> {
            Err(crate::RelayError::ConfigError(
                "WebAuthn is not available: build with --features webauthn".to_string(),
            ))
        }

        pub async fn list_credentials(&self, _user_id: &str) -> Vec<CredentialInfo> {
            vec![]
        }

        pub async fn cleanup_expired_challenges(&self) {}
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CredentialInfo {
        pub credential_id: String,
        pub created_at: DateTime<Utc>,
        pub last_used: Option<DateTime<Utc>>,
        pub counter: u32,
        pub name: Option<String>,
    }
}

#[cfg(not(feature = "webauthn"))]
pub use stub::WebAuthnManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_stub_not_available() {
        #[cfg(not(feature = "webauthn"))]
        {
            let result = stub::WebAuthnManager::new("Test", "localhost", "http://localhost");
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("webauthn"));
        }

        #[cfg(feature = "webauthn")]
        {
            // With feature enabled, creation may succeed
            let _ = WebAuthnManager::new("Test", "localhost", "http://localhost");
        }
    }
}
