//! API Key Management System
//!
//! Implements scoped API key authentication inspired by AWS IAM and GitHub:
//! - Scoped permissions (read-only, admin, relay, etc.)
//! - Automatic key rotation support
//! - Key expiration with configurable TTL
//! - Usage tracking and rate limiting per key

use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

/// API key manager
#[derive(Debug)]
pub struct ApiKeyManager {
    /// Stored API keys (key_id -> ApiKey)
    keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    /// Key prefix for identification
    key_prefix: String,
    /// Default key TTL
    default_ttl: Option<Duration>,
    /// Maximum keys per user
    max_keys_per_user: usize,
    /// Rate limiting per key
    rate_limits: Arc<RwLock<HashMap<String, RateLimitState>>>,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            key_prefix: "gptl".to_string(),
            default_ttl: Some(Duration::days(365)),
            max_keys_per_user: 10,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set key prefix
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Set default key TTL
    pub fn with_default_ttl(mut self, days: i64) -> Self {
        self.default_ttl = Some(Duration::days(days));
        self
    }

    /// Disable key expiration
    pub fn without_expiration(mut self) -> Self {
        self.default_ttl = None;
        self
    }

    /// Set maximum keys per user
    pub fn with_max_keys_per_user(mut self, max: usize) -> Self {
        self.max_keys_per_user = max;
        self
    }

    /// Generate a new API key
    pub async fn create_key(
        &self,
        user_id: &str,
        name: impl Into<String>,
        scopes: Vec<ApiKeyScope>,
        expires_in: Option<Duration>,
        metadata: Option<KeyMetadata>,
    ) -> crate::Result<ApiKeyCredentials> {
        // Check key limit
        {
            let keys = self.keys.read().await;
            let user_key_count = keys.values()
                .filter(|k| k.user_id == user_id && !k.revoked)
                .count();
            
            if user_key_count >= self.max_keys_per_user {
                return Err(crate::RelayError::AuthorizationFailed(
                    format!("Maximum {} API keys allowed per user", self.max_keys_per_user)
                ));
            }
        }

        // Generate key
        let key_id = generate_key_id(&self.key_prefix);
        let key_secret = generate_key_secret();
        let now = Utc::now();
        let expires_at = expires_in
            .or(self.default_ttl)
            .map(|ttl| now + ttl);

        let api_key = ApiKey {
            id: key_id.clone(),
            user_id: user_id.to_string(),
            name: name.into(),
            scopes: scopes.clone(),
            hashed_secret: hash_secret(&key_secret),
            created_at: now,
            expires_at,
            last_used: None,
            usage_count: 0,
            revoked: false,
            metadata: metadata.unwrap_or_default(),
            rotation_parent: None,
        };

        // Store key
        {
            let mut keys = self.keys.write().await;
            keys.insert(key_id.clone(), api_key);
        }

        Ok(ApiKeyCredentials {
            key_id: key_id.clone(),
            key_secret: key_secret.clone(),
            prefix: self.key_prefix.clone(),
            full_key: format!("{}_{}_{}", self.key_prefix, key_id, key_secret),
            scopes,
            created_at: now,
            expires_at,
        })
    }

    /// Validate an API key.
    ///
    /// Full key format: `{prefix}_{key_id}_{secret}`
    /// where `key_id` = `{prefix}_{uuid}` (contains an underscore),
    /// so the full key has the shape `{prefix}_{prefix}_{uuid}_{secret}`.
    /// We parse by stripping the leading `{prefix}_` and splitting on the
    /// last underscore to separate key_id from secret.
    pub async fn validate_key(
        &self,
        full_key: &str,
    ) -> crate::Result<ApiKeyValidation> {
        let prefix_sep = format!("{}_", self.key_prefix);
        if !full_key.starts_with(&prefix_sep) {
            return Err(crate::RelayError::InvalidApiKey);
        }
        let after_prefix = &full_key[prefix_sep.len()..];
        let last_sep = after_prefix.rfind('_').ok_or(crate::RelayError::InvalidApiKey)?;
        let key_id = &after_prefix[..last_sep];
        let provided_secret = &after_prefix[last_sep + 1..];

        // Get key
        let key = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
                .ok_or(crate::RelayError::InvalidApiKey)?
        };

        // Check if revoked
        if key.revoked {
            return Err(crate::RelayError::InvalidApiKey);
        }

        // Check expiration
        if let Some(expires_at) = key.expires_at {
            if expires_at < Utc::now() {
                return Err(crate::RelayError::ApiKeyExpired);
            }
        }

        // Verify secret
        if !verify_secret(provided_secret, &key.hashed_secret) {
            return Err(crate::RelayError::InvalidApiKey);
        }

        // Update usage
        {
            let mut keys = self.keys.write().await;
            if let Some(k) = keys.get_mut(key_id) {
                k.last_used = Some(Utc::now());
                k.usage_count += 1;
            }
        }

        Ok(ApiKeyValidation {
            key_id: key.id,
            user_id: key.user_id,
            scopes: key.scopes,
            name: key.name,
        })
    }

    /// Check if key has required scope.
    ///
    /// `Admin` grants all scopes.  `ReadWrite` implies `ReadOnly`.
    pub fn has_scope(&self, scopes: &[ApiKeyScope], required: ApiKeyScope) -> bool {
        if scopes.contains(&ApiKeyScope::Admin) {
            return true;
        }
        if scopes.contains(&required) {
            return true;
        }
        // Hierarchical: ReadWrite grants ReadOnly access
        if required == ApiKeyScope::ReadOnly && scopes.contains(&ApiKeyScope::ReadWrite) {
            return true;
        }
        false
    }

    /// Check if key has all required scopes
    pub fn has_all_scopes(&self, scopes: &[ApiKeyScope], required: &[ApiKeyScope]) -> bool {
        let has_admin = scopes.contains(&ApiKeyScope::Admin);
        
        required.iter().all(|req| {
            has_admin || scopes.contains(req)
        })
    }

    /// Revoke an API key
    pub async fn revoke_key(&self, key_id: &str) -> crate::Result<()> {
        let mut keys = self.keys.write().await;
        
        if let Some(key) = keys.get_mut(key_id) {
            key.revoked = true;
            Ok(())
        } else {
            Err(crate::RelayError::InvalidApiKey)
        }
    }

    /// Rotate an API key (create new, mark old for deletion)
    pub async fn rotate_key(&self, key_id: &str) -> crate::Result<ApiKeyCredentials> {
        let old_key = {
            let keys = self.keys.read().await;
            keys.get(key_id).cloned()
                .ok_or(crate::RelayError::InvalidApiKey)?
        };

        if old_key.revoked {
            return Err(crate::RelayError::InvalidApiKey);
        }

        // Create new key
        let new_credentials = self.create_key(
            &old_key.user_id,
            format!("{} (rotated)", old_key.name),
            old_key.scopes.clone(),
            self.default_ttl,
            Some(old_key.metadata.clone()),
        ).await?;

        // Mark old key as rotated
        {
            let mut keys = self.keys.write().await;
            if let Some(key) = keys.get_mut(key_id) {
                key.revoked = true;
                key.metadata.rotation_replaced_by = Some(new_credentials.key_id.clone());
            }
            if let Some(key) = keys.get_mut(&new_credentials.key_id) {
                key.rotation_parent = Some(key_id.to_string());
            }
        }

        Ok(new_credentials)
    }

    /// List API keys for a user
    pub async fn list_user_keys(&self, user_id: &str) -> Vec<ApiKeyInfo> {
        let keys = self.keys.read().await;
        
        keys.values()
            .filter(|k| k.user_id == user_id)
            .map(|k| ApiKeyInfo {
                id: k.id.clone(),
                name: k.name.clone(),
                scopes: k.scopes.clone(),
                created_at: k.created_at,
                expires_at: k.expires_at,
                last_used: k.last_used,
                usage_count: k.usage_count,
                revoked: k.revoked,
                metadata: k.metadata.clone(),
            })
            .collect()
    }

    /// Get API key details
    pub async fn get_key(&self, key_id: &str) -> Option<ApiKeyInfo> {
        let keys = self.keys.read().await;
        
        keys.get(key_id).map(|k| ApiKeyInfo {
            id: k.id.clone(),
            name: k.name.clone(),
            scopes: k.scopes.clone(),
            created_at: k.created_at,
            expires_at: k.expires_at,
            last_used: k.last_used,
            usage_count: k.usage_count,
            revoked: k.revoked,
            metadata: k.metadata.clone(),
        })
    }

    /// Check rate limit for a key
    pub async fn check_rate_limit(&self, key_id: &str, quota: &RateLimitQuota) -> crate::Result<()> {
        let mut limits = self.rate_limits.write().await;
        let now = Utc::now();
        
        let state = limits.entry(key_id.to_string())
            .or_insert_with(|| RateLimitState {
                requests: 0,
                window_start: now,
            });

        // Reset window if expired
        if state.window_start + quota.window < now {
            state.requests = 0;
            state.window_start = now;
        }

        if state.requests >= quota.requests {
            let retry_after = (state.window_start + quota.window - now).num_seconds() as u64;
            return Err(crate::RelayError::RateLimitExceeded(retry_after));
        }

        state.requests += 1;
        Ok(())
    }

    /// Cleanup expired keys
    pub async fn cleanup_expired(&self) {
        let mut keys = self.keys.write().await;
        let now = Utc::now();
        
        keys.retain(|_, key| {
            !key.revoked && key.expires_at.map(|e| e > now).unwrap_or(true)
        });
    }

    /// Get API key statistics
    pub async fn get_stats(&self) -> ApiKeyStats {
        let keys = self.keys.read().await;
        
        let total = keys.len() as u64;
        let active = keys.values().filter(|k| !k.revoked && k.expires_at.map(|e| e > Utc::now()).unwrap_or(true)).count() as u64;
        let revoked = keys.values().filter(|k| k.revoked).count() as u64;
        let expired = keys.values().filter(|k| k.expires_at.map(|e| e <= Utc::now()).unwrap_or(false)).count() as u64;
        
        ApiKeyStats {
            total_keys: total,
            active_keys: active,
            revoked_keys: revoked,
            expired_keys: expired,
        }
    }
}

impl Default for ApiKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// API key scope/permission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Read-only access
    ReadOnly,
    /// Read-write access
    ReadWrite,
    /// Relay operations
    Relay,
    /// Administrative operations
    Admin,
    /// Audit log access
    Audit,
    /// User management
    Users,
    /// Configuration management
    Config,
}

impl ApiKeyScope {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ApiKeyScope::ReadOnly => "Read-only access to resources",
            ApiKeyScope::ReadWrite => "Read and write access to resources",
            ApiKeyScope::Relay => "Relay operations",
            ApiKeyScope::Admin => "Full administrative access",
            ApiKeyScope::Audit => "Access to audit logs",
            ApiKeyScope::Users => "User management",
            ApiKeyScope::Config => "Configuration management",
        }
    }
}

/// API key stored in the system
#[derive(Debug, Clone)]
struct ApiKey {
    id: String,
    user_id: String,
    name: String,
    scopes: Vec<ApiKeyScope>,
    hashed_secret: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used: Option<DateTime<Utc>>,
    usage_count: u64,
    revoked: bool,
    metadata: KeyMetadata,
    rotation_parent: Option<String>,
}

/// API key metadata
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    pub description: Option<String>,
    pub ip_restrictions: Vec<String>,
    pub rotation_replaced_by: Option<String>,
    pub custom_data: HashMap<String, String>,
}

/// API key credentials (returned once on creation)
#[derive(Debug, Clone)]
pub struct ApiKeyCredentials {
    pub key_id: String,
    pub key_secret: String,
    pub prefix: String,
    pub full_key: String,
    pub scopes: Vec<ApiKeyScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// API key validation result
#[derive(Debug, Clone)]
pub struct ApiKeyValidation {
    pub key_id: String,
    pub user_id: String,
    pub scopes: Vec<ApiKeyScope>,
    pub name: String,
}

/// API key information (safe to display)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<ApiKeyScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub usage_count: u64,
    pub revoked: bool,
    pub metadata: KeyMetadata,
}

/// Rate limit quota
#[derive(Debug, Clone)]
pub struct RateLimitQuota {
    pub requests: u32,
    pub window: Duration,
}

impl Default for RateLimitQuota {
    fn default() -> Self {
        Self {
            requests: 1000,
            window: Duration::hours(1),
        }
    }
}

/// Rate limit state per key
#[derive(Debug, Clone)]
struct RateLimitState {
    requests: u32,
    window_start: DateTime<Utc>,
}

/// API key statistics
#[derive(Debug, Clone, Default)]
pub struct ApiKeyStats {
    pub total_keys: u64,
    pub active_keys: u64,
    pub revoked_keys: u64,
    pub expired_keys: u64,
}

/// Generate a unique key ID
fn generate_key_id(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4().simple())
}

/// Generate a secure random key secret
fn generate_key_secret() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const LEN: usize = 48;
    
    let mut rng = rand::thread_rng();
    (0..LEN)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Hash a secret for storage
fn hash_secret(secret: &str) -> String {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Verify a secret against a hash
fn verify_secret(secret: &str, hash: &str) -> bool {
    hash_secret(secret) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_api_key_creation() {
        let manager = ApiKeyManager::new();

        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![ApiKeyScope::ReadOnly],
            None,
            None,
        ).await.unwrap();

        assert!(!credentials.key_id.is_empty());
        assert!(!credentials.key_secret.is_empty());
        assert!(credentials.full_key.starts_with("gptl_"));
        assert_eq!(credentials.scopes, vec![ApiKeyScope::ReadOnly]);
    }

    #[tokio::test]
    async fn test_api_key_validation() {
        let manager = ApiKeyManager::new();

        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![ApiKeyScope::ReadWrite],
            None,
            None,
        ).await.unwrap();

        // Valid key
        let validation = manager.validate_key(&credentials.full_key).await.unwrap();
        assert_eq!(validation.user_id, "user123");
        assert_eq!(validation.scopes, vec![ApiKeyScope::ReadWrite]);

        // Invalid key
        let result = manager.validate_key("invalid_key").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_api_key_revocation() {
        let manager = ApiKeyManager::new();

        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![ApiKeyScope::ReadOnly],
            None,
            None,
        ).await.unwrap();

        // Revoke key
        manager.revoke_key(&credentials.key_id).await.unwrap();

        // Should be invalid now
        let result = manager.validate_key(&credentials.full_key).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_scope_checking() {
        let manager = ApiKeyManager::new();

        let scopes = vec![ApiKeyScope::ReadWrite];

        assert!(manager.has_scope(&scopes, ApiKeyScope::ReadOnly));
        assert!(manager.has_scope(&scopes, ApiKeyScope::ReadWrite));
        assert!(!manager.has_scope(&scopes, ApiKeyScope::Admin));

        // Admin scope grants all permissions
        let admin_scopes = vec![ApiKeyScope::Admin];
        assert!(manager.has_scope(&admin_scopes, ApiKeyScope::ReadOnly));
        assert!(manager.has_scope(&admin_scopes, ApiKeyScope::Config));
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = ApiKeyManager::new();

        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![ApiKeyScope::ReadOnly],
            None,
            None,
        ).await.unwrap();

        // Rotate key
        let new_credentials = manager.rotate_key(&credentials.key_id).await.unwrap();

        // Old key should be revoked
        assert!(manager.validate_key(&credentials.full_key).await.is_err());

        // New key should work
        let validation = manager.validate_key(&new_credentials.full_key).await.unwrap();
        assert_eq!(validation.user_id, "user123");
    }

    #[tokio::test]
    async fn test_max_keys_per_user() {
        let manager = ApiKeyManager::new().with_max_keys_per_user(2);

        // Create 2 keys (should succeed)
        manager.create_key("user123", "Key 1", vec![], None, None).await.unwrap();
        manager.create_key("user123", "Key 2", vec![], None, None).await.unwrap();

        // 3rd key should fail
        let result = manager.create_key("user123", "Key 3", vec![], None, None).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_key_generation() {
        let id = generate_key_id("gptl");
        assert!(id.starts_with("gptl_"));
        assert_eq!(id.len(), 4 + 1 + 32); // "gptl"(4) + "_"(1) + uuid-simple(32)

        let secret = generate_key_secret();
        assert_eq!(secret.len(), 48);
        assert!(secret.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[tokio::test]
    async fn test_key_expiration() {
        let manager = ApiKeyManager::new();

        // Create key with short expiration
        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![ApiKeyScope::ReadOnly],
            Some(Duration::seconds(-1)), // Already expired
            None,
        ).await.unwrap();

        // Should fail validation due to expiration
        let result = manager.validate_key(&credentials.full_key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_user_keys() {
        let manager = ApiKeyManager::new();

        manager.create_key("user123", "Key 1", vec![], None, None).await.unwrap();
        manager.create_key("user123", "Key 2", vec![], None, None).await.unwrap();
        manager.create_key("user456", "Key 3", vec![], None, None).await.unwrap();

        let keys = manager.list_user_keys("user123").await;
        assert_eq!(keys.len(), 2);

        let keys = manager.list_user_keys("user456").await;
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let manager = ApiKeyManager::new();

        let credentials = manager.create_key(
            "user123",
            "Test Key",
            vec![],
            None,
            None,
        ).await.unwrap();

        let quota = RateLimitQuota {
            requests: 2,
            window: Duration::seconds(10),
        };

        // First 2 requests should succeed
        assert!(manager.check_rate_limit(&credentials.key_id, &quota).await.is_ok());
        assert!(manager.check_rate_limit(&credentials.key_id, &quota).await.is_ok());

        // 3rd request should fail
        let result = manager.check_rate_limit(&credentials.key_id, &quota).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let manager = ApiKeyManager::new();

        // Create expired key
        manager.create_key(
            "user123",
            "Expired Key",
            vec![],
            Some(Duration::seconds(-1)),
            None,
        ).await.unwrap();

        // Create valid key
        manager.create_key(
            "user123",
            "Valid Key",
            vec![],
            None,
            None,
        ).await.unwrap();

        manager.cleanup_expired().await;

        let keys = manager.list_user_keys("user123").await;
        // Only valid key should remain
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "Valid Key");
    }

    #[tokio::test]
    async fn test_api_key_stats() {
        let manager = ApiKeyManager::new();

        manager.create_key("user1", "Key 1", vec![], None, None).await.unwrap();
        let creds = manager.create_key("user2", "Key 2", vec![], None, None).await.unwrap();

        manager.revoke_key(&creds.key_id).await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_keys, 2);
        assert_eq!(stats.active_keys, 1);
        assert_eq!(stats.revoked_keys, 1);
    }

    #[tokio::test]
    async fn test_scope_descriptions() {
        assert!(!ApiKeyScope::ReadOnly.description().is_empty());
        assert!(!ApiKeyScope::Admin.description().is_empty());
    }

    #[tokio::test]
    async fn test_has_all_scopes() {
        let manager = ApiKeyManager::new();

        let scopes = vec![ApiKeyScope::ReadWrite, ApiKeyScope::Audit];
        let required = vec![ApiKeyScope::ReadWrite, ApiKeyScope::Audit];

        assert!(manager.has_all_scopes(&scopes, &required));

        let required_missing = vec![ApiKeyScope::ReadWrite, ApiKeyScope::Admin];
        assert!(!manager.has_all_scopes(&scopes, &required_missing));
    }

    #[test]
    fn test_hash_secret() {
        let secret = "test_secret";
        let hash1 = hash_secret(secret);
        let hash2 = hash_secret(secret);

        // Same secret should produce same hash
        assert_eq!(hash1, hash2);

        // Different secret should produce different hash
        let hash3 = hash_secret("different_secret");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_verify_secret() {
        let secret = "test_secret";
        let hash = hash_secret(secret);

        assert!(verify_secret(secret, &hash));
        assert!(!verify_secret("wrong_secret", &hash));
    }
}
