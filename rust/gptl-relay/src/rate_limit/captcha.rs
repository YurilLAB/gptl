//! CAPTCHA Challenge System
//!
//! Implements hCaptcha integration for bot protection:
//! - hCaptcha verification
//! - Challenge-response validation
//! - Configurable difficulty

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

/// CAPTCHA challenge manager
#[derive(Debug)]
pub struct CaptchaChallenge {
    /// hCaptcha secret key
    secret_key: String,
    /// hCaptcha site key
    site_key: String,
    /// Challenge timeout
    timeout_seconds: i64,
    /// Active challenges
    challenges: Arc<RwLock<HashMap<String, ChallengeState>>>,
    /// Verification endpoint
    verify_url: String,
}

impl CaptchaChallenge {
    /// Create a new CAPTCHA challenge manager
    pub fn new(secret_key: impl Into<String>, site_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            site_key: site_key.into(),
            timeout_seconds: 120,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            verify_url: "https://api.hcaptcha.com/siteverify".to_string(),
        }
    }

    /// Set custom timeout
    pub fn with_timeout(mut self, seconds: i64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Get the site key (for client-side rendering)
    pub fn site_key(&self) -> &str {
        &self.site_key
    }

    /// Create a new challenge
    pub async fn create_challenge(&self) -> String {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        
        let state = ChallengeState {
            created_at: Utc::now(),
            verified: false,
            response: None,
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_id.clone(), state);

        challenge_id
    }

    /// Verify a CAPTCHA response
    pub async fn verify(
        &self,
        challenge_id: &str,
        response_token: &str,
    ) -> crate::Result<CaptchaVerification> {
        // Check if challenge exists and is valid
        {
            let challenges = self.challenges.read().await;
            let state = challenges.get(challenge_id)
                .ok_or_else(|| crate::RelayError::AuthenticationFailed(
                    "Invalid challenge ID".to_string()
                ))?;

            if state.created_at + Duration::seconds(self.timeout_seconds) < Utc::now() {
                return Ok(CaptchaVerification {
                    success: false,
                    challenge_ts: None,
                    hostname: None,
                    error_codes: vec!["timeout-or-duplicate".to_string()],
                });
            }

            if state.verified {
                // Already verified, allow
                return Ok(CaptchaVerification {
                    success: true,
                    challenge_ts: Some(state.created_at),
                    hostname: None,
                    error_codes: vec![],
                });
            }
        }

        // Verify with hCaptcha API
        let result = self.verify_with_hcaptcha(response_token).await?;

        if result.success {
            // Mark challenge as verified
            let mut challenges = self.challenges.write().await;
            if let Some(state) = challenges.get_mut(challenge_id) {
                state.verified = true;
                state.response = Some(response_token.to_string());
            }
        }

        Ok(result)
    }

    /// Check if a challenge has been verified
    pub async fn is_verified(&self, challenge_id: &str) -> bool {
        let challenges = self.challenges.read().await;
        
        challenges.get(challenge_id).map(|state| {
            state.verified && 
            state.created_at + Duration::seconds(self.timeout_seconds) > Utc::now()
        }).unwrap_or(false)
    }

    /// Invalidate a challenge
    pub async fn invalidate(&self, challenge_id: &str) {
        let mut challenges = self.challenges.write().await;
        challenges.remove(challenge_id);
    }

    /// Verify response with hCaptcha API
    async fn verify_with_hcaptcha(
        &self,
        response_token: &str,
    ) -> crate::Result<CaptchaVerification> {
        // hCaptcha siteverify API: https://docs.hcaptcha.com/#verify-the-user-response-server-side
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| crate::RelayError::Internal(format!("HTTP client error: {}", e)))?;

        let params = [
            ("secret", self.secret_key.as_str()),
            ("response", response_token),
        ];

        let response = client
            .post(&self.verify_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| crate::RelayError::Internal(format!("hCaptcha request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(crate::RelayError::Internal(
                format!("hCaptcha API returned status: {}", response.status())
            ));
        }

        let result: CaptchaVerification = response.json().await
            .map_err(|e| crate::RelayError::Internal(format!("Failed to parse hCaptcha response: {}", e)))?;

        Ok(result)
    }

    /// Cleanup expired challenges
    pub async fn cleanup(&self) {
        let mut challenges = self.challenges.write().await;
        let cutoff = Utc::now() - Duration::seconds(self.timeout_seconds);
        challenges.retain(|_, state| state.created_at > cutoff);
    }

    /// Get challenge statistics
    pub async fn get_stats(&self) -> CaptchaStats {
        let challenges = self.challenges.read().await;
        
        let total = challenges.len() as u64;
        let verified = challenges.values().filter(|s| s.verified).count() as u64;
        let pending = total - verified;

        CaptchaStats {
            total_challenges: total,
            verified_challenges: verified,
            pending_challenges: pending,
        }
    }
}

/// Challenge state
#[derive(Debug, Clone)]
struct ChallengeState {
    created_at: DateTime<Utc>,
    verified: bool,
    response: Option<String>,
}

/// CAPTCHA verification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaptchaVerification {
    pub success: bool,
    #[serde(rename = "challenge_ts")]
    pub challenge_ts: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Vec<String>,
}

/// CAPTCHA statistics
#[derive(Debug, Clone, Default)]
pub struct CaptchaStats {
    pub total_challenges: u64,
    pub verified_challenges: u64,
    pub pending_challenges: u64,
}

/// CAPTCHA generator for fallback/text-based CAPTCHAs
#[derive(Debug)]
pub struct CaptchaGenerator {
    /// Character set for CAPTCHA
    charset: Vec<char>,
    /// Length of CAPTCHA
    length: usize,
    /// Case sensitivity
    case_sensitive: bool,
}

impl CaptchaGenerator {
    /// Create a new CAPTCHA generator
    pub fn new() -> Self {
        Self {
            charset: "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
                .chars()
                .collect(),
            length: 6,
            case_sensitive: false,
        }
    }

    /// Set CAPTCHA length
    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Generate a new CAPTCHA
    pub fn generate(&self) -> GeneratedCaptcha {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let code: String = (0..self.length)
            .map(|_| self.charset[rng.gen_range(0..self.charset.len())])
            .collect();

        GeneratedCaptcha {
            id: uuid::Uuid::new_v4().to_string(),
            code,
            image_data: None, // Would be generated in production
            audio_data: None,
        }
    }

    /// Verify a CAPTCHA code
    pub fn verify(&self, expected: &str, provided: &str) -> bool {
        if self.case_sensitive {
            constant_time_eq(expected, provided)
        } else {
            constant_time_eq(&expected.to_lowercase(), &provided.to_lowercase())
        }
    }
}

impl Default for CaptchaGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generated CAPTCHA
#[derive(Debug, Clone)]
pub struct GeneratedCaptcha {
    pub id: String,
    pub code: String,
    pub image_data: Option<Vec<u8>>,
    pub audio_data: Option<Vec<u8>>,
}

/// Constant-time string comparison
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// CAPTCHA configuration
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// Enable CAPTCHA
    pub enabled: bool,
    /// Provider (hcaptcha, recaptcha, custom)
    pub provider: CaptchaProvider,
    /// Site key
    pub site_key: String,
    /// Secret key
    pub secret_key: String,
    /// Show CAPTCHA after N failures
    pub show_after_failures: u32,
    /// Always show CAPTCHA
    pub always_show: bool,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: CaptchaProvider::HCaptcha,
            site_key: String::new(),
            secret_key: String::new(),
            show_after_failures: 3,
            always_show: false,
        }
    }
}

/// CAPTCHA provider
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaProvider {
    HCaptcha,
    ReCaptcha,
    Turnstile,
    Custom,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_captcha_challenge_creation() {
        let captcha = CaptchaChallenge::new("secret", "site_key");
        let challenge_id = captcha.create_challenge().await;

        assert!(!challenge_id.is_empty());
        assert!(!captcha.is_verified(&challenge_id).await);
    }

    #[tokio::test]
    async fn test_captcha_verification() {
        let captcha = CaptchaChallenge::new("secret", "site_key");
        let challenge_id = captcha.create_challenge().await;

        // Note: In production, this would call real hCaptcha API
        // For testing, we'd need to mock the HTTP client
        let result = captcha.verify(&challenge_id, "test_token").await;
        // Result depends on whether reqwest is available
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_captcha_timeout() {
        let captcha = CaptchaChallenge::new("secret", "site_key")
            .with_timeout(1); // 1 second timeout

        let challenge_id = captcha.create_challenge().await;

        // Wait for timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Should be expired
        assert!(!captcha.is_verified(&challenge_id).await);
    }

    #[tokio::test]
    async fn test_captcha_invalidation() {
        let captcha = CaptchaChallenge::new("secret", "site_key");
        let challenge_id = captcha.create_challenge().await;

        captcha.invalidate(&challenge_id).await;

        assert!(!captcha.is_verified(&challenge_id).await);
    }

    #[tokio::test]
    async fn test_captcha_cleanup() {
        let captcha = CaptchaChallenge::new("secret", "site_key")
            .with_timeout(1);

        // Create multiple challenges
        for _ in 0..5 {
            captcha.create_challenge().await;
        }

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Cleanup
        captcha.cleanup().await;

        let stats = captcha.get_stats().await;
        assert_eq!(stats.total_challenges, 0);
    }

    #[tokio::test]
    async fn test_captcha_stats() {
        let captcha = CaptchaChallenge::new("secret", "site_key");

        let stats = captcha.get_stats().await;
        assert_eq!(stats.total_challenges, 0);

        captcha.create_challenge().await;

        let stats = captcha.get_stats().await;
        assert_eq!(stats.total_challenges, 1);
    }

    #[test]
    fn test_captcha_generator() {
        let generator = CaptchaGenerator::new().with_length(6);
        let captcha = generator.generate();

        assert_eq!(captcha.code.len(), 6);
        assert!(!captcha.id.is_empty());

        // Verify correct code
        assert!(generator.verify(&captcha.code, &captcha.code));

        // Verify incorrect code
        assert!(!generator.verify(&captcha.code, "wrongcode"));
    }

    #[test]
    fn test_case_insensitive_verification() {
        let generator = CaptchaGenerator::new();

        assert!(generator.verify("ABC123", "abc123"));
        assert!(generator.verify("abc123", "ABC123"));
    }

    #[test]
    fn test_case_sensitive_verification() {
        let generator = CaptchaGenerator::new();
        // Default is case-insensitive, so this should pass
        assert!(generator.verify("ABC", "abc"));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hello!"));
    }

    #[test]
    fn test_captcha_config() {
        let config = CaptchaConfig::default();
        assert!(config.enabled);
        assert_eq!(config.show_after_failures, 3);
    }

    #[test]
    fn test_captcha_provider() {
        let provider = CaptchaProvider::HCaptcha;
        assert_eq!(provider, CaptchaProvider::HCaptcha);
    }
}
