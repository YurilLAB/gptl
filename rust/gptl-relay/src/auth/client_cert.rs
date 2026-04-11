//! Client certificate authentication
use std::collections::HashMap;

use std::sync::Arc;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// Client certificate verifier
#[derive(Debug)]
pub struct ClientCertVerifier {
    allowed_certs: Arc<RwLock<HashMap<String, AllowedCert>>>,
}

impl ClientCertVerifier {
    /// Create new verifier
    pub fn new() -> Self {
        Self {
            allowed_certs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Verify certificate
    pub async fn verify_certificate(&self, certificate: &ClientCertificate) -> crate::Result<String> {
        let fingerprint = self.calculate_fingerprint(certificate);
        let certs = self.allowed_certs.read().await;
        
        let allowed = certs.get(&fingerprint)
            .ok_or_else(|| crate::RelayError::AuthenticationFailed("Certificate not authorized".to_string()))?;
        
        if allowed.revoked {
            return Err(crate::RelayError::AuthenticationFailed("Certificate revoked".to_string()));
        }
        
        Ok(allowed.user_id.clone())
    }

    /// Allow certificate for user
    pub async fn allow_certificate(&self, user_id: &str, cert_fingerprint: &str) -> crate::Result<()> {
        let mut certs = self.allowed_certs.write().await;
        certs.insert(cert_fingerprint.to_string(), AllowedCert {
            user_id: user_id.to_string(),
            fingerprint: cert_fingerprint.to_string(),
            created_at: Utc::now(),
            last_used: None,
            revoked: false,
        });
        Ok(())
    }

    /// Calculate fingerprint
    fn calculate_fingerprint(&self, certificate: &ClientCertificate) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&certificate.raw_der);
        hex::encode(hasher.finalize())
    }
}

impl Default for ClientCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Client certificate
#[derive(Debug, Clone)]
pub struct ClientCertificate {
    pub raw_der: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub subject_alternative_names: Vec<String>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Allowed certificate
#[derive(Debug, Clone)]
struct AllowedCert {
    user_id: String,
    fingerprint: String,
    created_at: DateTime<Utc>,
    last_used: Option<DateTime<Utc>>,
    revoked: bool,
}
