//! Relay Registry Module
//!
//! Provides secure relay registration, storage, and discovery:
//! - RelayInfo: Metadata for relay nodes
//! - RelayRegistry trait: Abstract storage backend
//! - InMemoryRegistry: Testing and ephemeral storage
//! - JsonFileRegistry: Persistent local storage
//! - Secure registration with proof of ownership

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

/// Security level for relays
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Standard security (basic encryption)
    Standard,
    /// Enhanced security (forward secrecy, additional protections)
    Enhanced,
    /// Maximum security (all protections enabled)
    Maximum,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Enhanced
    }
}

/// Health status of a relay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Relay is healthy and accepting connections
    Healthy,
    /// Relay is experiencing issues
    Degraded,
    /// Relay is offline or unreachable
    Offline,
    /// Relay is under maintenance
    Maintenance,
    /// Relay has been banned
    Banned,
}

impl Default for HealthStatus {
    fn default() -> Self {
        HealthStatus::Healthy
    }
}

impl HealthStatus {
    /// Check if the relay is usable
    pub fn is_usable(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

/// Geographic location information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Location {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<i32>, // Stored as microdegrees for precision
    /// Longitude
    pub longitude: Option<i32>, // Stored as microdegrees for precision
}

/// Relay capabilities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct RelayCapabilities {
    /// Supports IPv4
    pub ipv4: bool,
    /// Supports IPv6
    pub ipv6: bool,
    /// Supports onion routing
    pub onion_routing: bool,
    /// Supports bridge mode
    pub bridge_mode: bool,
    /// Supports pluggable transports
    pub pluggable_transports: Vec<String>,
    /// Exit relay capabilities (if any)
    pub exit_policy: Option<ExitPolicy>,
}

/// Exit policy for exit relays
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExitPolicy {
    /// Allowed ports
    pub allowed_ports: Vec<u16>,
    /// Blocked ports
    pub blocked_ports: Vec<u16>,
    /// Allowed destinations (IP ranges or domains)
    pub allowed_destinations: Vec<String>,
    /// Blocked destinations
    pub blocked_destinations: Vec<String>,
}

/// Relay information
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Unique relay ID
    pub id: String,
    /// Relay address (IP:port or hostname:port)
    pub address: String,
    /// Relay's public key (base64 encoded ed25519 key)
    pub public_key: String,
    /// Relay bandwidth in bytes/second
    pub bandwidth: u64,
    /// Geographic location
    pub location: Location,
    /// Security level supported
    pub security_level: SecurityLevel,
    /// Current health status
    pub health_status: HealthStatus,
    /// Relay capabilities
    pub capabilities: RelayCapabilities,
    /// When the relay was registered
    pub registered_at: SystemTime,
    /// Last health check timestamp
    pub last_seen: SystemTime,
    /// Relay version
    pub version: String,
    /// Relay nickname/alias
    pub nickname: Option<String>,
    /// Contact information (optional, encrypted)
    pub contact: Option<String>,
    /// Proof of ownership (signature)
    pub ownership_proof: Option<String>,
}

impl RelayInfo {
    /// Create a new relay info
    pub fn new(
        address: impl Into<String>,
        public_key: impl Into<String>,
        bandwidth: u64,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4().to_string(),
            address: address.into(),
            public_key: public_key.into(),
            bandwidth,
            location: Location::default(),
            security_level: SecurityLevel::default(),
            health_status: HealthStatus::default(),
            capabilities: RelayCapabilities::default(),
            registered_at: now,
            last_seen: now,
            version: "0.1.0".to_string(),
            nickname: None,
            contact: None,
            ownership_proof: None,
        }
    }

    /// Set the relay location
    pub fn with_location(mut self, location: Location) -> Self {
        self.location = location;
        self
    }

    /// Set the security level
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    /// Set the nickname
    pub fn with_nickname(mut self, nickname: impl Into<String>) -> Self {
        self.nickname = Some(nickname.into());
        self
    }

    /// Set capabilities
    pub fn with_capabilities(mut self, capabilities: RelayCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Check if relay matches criteria
    pub fn matches_criteria(&self, criteria: &RelayCriteria) -> bool {
        // Check security level
        if let Some(min_level) = criteria.min_security_level {
            let level_ord = match (self.security_level, min_level) {
                (SecurityLevel::Maximum, _) => true,
                (SecurityLevel::Enhanced, SecurityLevel::Standard) |
                (SecurityLevel::Enhanced, SecurityLevel::Enhanced) => true,
                (SecurityLevel::Standard, SecurityLevel::Standard) => true,
                _ => false,
            };
            if !level_ord {
                return false;
            }
        }

        // Check minimum bandwidth
        if let Some(min_bw) = criteria.min_bandwidth {
            if self.bandwidth < min_bw {
                return false;
            }
        }

        // Check region
        if let Some(ref region) = criteria.region {
            if self.location.country_code.as_ref() != Some(region) {
                return false;
            }
        }

        // Check health status
        if criteria.require_healthy && !self.health_status.is_usable() {
            return false;
        }

        // Check excluded relays
        if criteria.excluded_ids.contains(&self.id) {
            return false;
        }

        // Check capabilities
        if criteria.require_ipv6 && !self.capabilities.ipv6 {
            return false;
        }

        if criteria.require_onion && !self.capabilities.onion_routing {
            return false;
        }

        true
    }

    /// Verify ownership proof
    pub fn verify_ownership(&self) -> Result<bool, RegistryError> {
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let proof = match &self.ownership_proof {
            Some(p) => p,
            None => return Ok(false),
        };

        // Decode public key
        let pk_bytes = BASE64.decode(&self.public_key)
            .map_err(|e| RegistryError::InvalidKey(format!("Invalid public key: {}", e)))?;
        
        if pk_bytes.len() != 32 {
            return Err(RegistryError::InvalidKey("Public key must be 32 bytes".to_string()));
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pk_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| RegistryError::InvalidKey(format!("Invalid verifying key: {:?}", e)))?;

        // Decode signature
        let sig_bytes = BASE64.decode(proof)
            .map_err(|e| RegistryError::InvalidProof(format!("Invalid proof: {}", e)))?;
        
        if sig_bytes.len() != 64 {
            return Err(RegistryError::InvalidProof("Signature must be 64 bytes".to_string()));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // Create message to verify (relay ID + address)
        let message = format!("{}:{}", self.id, self.address);

        // Verify signature
        match verifying_key.verify(message.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Criteria for filtering relays
#[derive(Debug, Clone, Default)]
pub struct RelayCriteria {
    /// Minimum security level required
    pub min_security_level: Option<SecurityLevel>,
    /// Minimum bandwidth required (bytes/sec)
    pub min_bandwidth: Option<u64>,
    /// Region/country code preference
    pub region: Option<String>,
    /// Require healthy status
    pub require_healthy: bool,
    /// Relay IDs to exclude
    pub excluded_ids: Vec<String>,
    /// Require IPv6 support
    pub require_ipv6: bool,
    /// Require onion routing support
    pub require_onion: bool,
    /// Maximum age since last seen
    pub max_age: Option<Duration>,
}

impl RelayCriteria {
    /// Create new criteria
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum security level
    pub fn with_min_security_level(mut self, level: SecurityLevel) -> Self {
        self.min_security_level = Some(level);
        self
    }

    /// Set minimum bandwidth
    pub fn with_min_bandwidth(mut self, bandwidth: u64) -> Self {
        self.min_bandwidth = Some(bandwidth);
        self
    }

    /// Set region preference
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Require healthy status
    pub fn require_healthy(mut self) -> Self {
        self.require_healthy = true;
        self
    }

    /// Exclude relay IDs
    pub fn with_excluded_ids(mut self, ids: Vec<String>) -> Self {
        self.excluded_ids = ids;
        self
    }

    /// Require IPv6 support
    pub fn require_ipv6(mut self) -> Self {
        self.require_ipv6 = true;
        self
    }

    /// Require onion routing
    pub fn require_onion(mut self) -> Self {
        self.require_onion = true;
        self
    }

    /// Set maximum age
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = Some(age);
        self
    }
}

/// Registry errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Relay not found: {0}")]
    NotFound(String),
    #[error("Relay already exists: {0}")]
    AlreadyExists(String),
    #[error("Invalid relay data: {0}")]
    InvalidData(String),
    #[error("Invalid public key: {0}")]
    InvalidKey(String),
    #[error("Invalid ownership proof: {0}")]
    InvalidProof(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Rate limit exceeded")]
    RateLimited,
}

/// Relay registry trait
#[async_trait::async_trait]
pub trait RelayRegistry: Send + Sync {
    /// Register a new relay
    async fn register(&self, relay: RelayInfo) -> Result<(), RegistryError>;

    /// Unregister a relay
    async fn unregister(&self, relay_id: &str) -> Result<(), RegistryError>;

    /// Get relay by ID
    async fn get_relay(&self, relay_id: &str) -> Result<RelayInfo, RegistryError>;

    /// Get relay by address
    async fn get_relay_by_address(&self, address: &str) -> Result<RelayInfo, RegistryError>;

    /// List all relays
    async fn list_relays(&self) -> Result<Vec<RelayInfo>, RegistryError>;

    /// List relays matching criteria
    async fn list_matching(&self, criteria: &RelayCriteria) -> Result<Vec<RelayInfo>, RegistryError>;

    /// Update relay health status
    async fn update_health(&self, relay_id: &str, status: HealthStatus) -> Result<(), RegistryError>;

    /// Update relay last_seen timestamp
    async fn update_last_seen(&self, relay_id: &str) -> Result<(), RegistryError>;

    /// Update relay bandwidth
    async fn update_bandwidth(&self, relay_id: &str, bandwidth: u64) -> Result<(), RegistryError>;

    /// Verify relay ownership
    async fn verify_ownership(&self, relay_id: &str) -> Result<bool, RegistryError>;

    /// Get total relay count
    async fn count(&self) -> Result<usize, RegistryError>;

    /// Get healthy relay count
    async fn healthy_count(&self) -> Result<usize, RegistryError>;
}

/// In-memory relay registry for testing
pub struct InMemoryRegistry {
    relays: Arc<RwLock<HashMap<String, RelayInfo>>>,
}

impl InMemoryRegistry {
    /// Create a new in-memory registry
    pub fn new() -> Self {
        Self {
            relays: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with pre-populated relays
    pub fn with_relays(relays: Vec<RelayInfo>) -> Self {
        let map: HashMap<String, RelayInfo> = relays
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();
        
        Self {
            relays: Arc::new(RwLock::new(map)),
        }
    }

    /// Clear all relays
    pub async fn clear(&self) {
        let mut relays = self.relays.write().await;
        relays.clear();
    }
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl RelayRegistry for InMemoryRegistry {
    async fn register(&self, relay: RelayInfo) -> Result<(), RegistryError> {
        let mut relays = self.relays.write().await;
        
        if relays.contains_key(&relay.id) {
            return Err(RegistryError::AlreadyExists(relay.id));
        }

        // Check for duplicate address
        for existing in relays.values() {
            if existing.address == relay.address {
                return Err(RegistryError::AlreadyExists(
                    format!("Address {} already registered", relay.address)
                ));
            }
        }

        debug!("Registering relay {} at {}", relay.id, relay.address);
        relays.insert(relay.id.clone(), relay);
        Ok(())
    }

    async fn unregister(&self, relay_id: &str) -> Result<(), RegistryError> {
        let mut relays = self.relays.write().await;
        
        if relays.remove(relay_id).is_none() {
            return Err(RegistryError::NotFound(relay_id.to_string()));
        }

        debug!("Unregistered relay {}", relay_id);
        Ok(())
    }

    async fn get_relay(&self, relay_id: &str) -> Result<RelayInfo, RegistryError> {
        let relays = self.relays.read().await;
        
        relays
            .get(relay_id)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(relay_id.to_string()))
    }

    async fn get_relay_by_address(&self, address: &str) -> Result<RelayInfo, RegistryError> {
        let relays = self.relays.read().await;
        
        relays
            .values()
            .find(|r| r.address == address)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(format!("Address: {}", address)))
    }

    async fn list_relays(&self) -> Result<Vec<RelayInfo>, RegistryError> {
        let relays = self.relays.read().await;
        Ok(relays.values().cloned().collect())
    }

    async fn list_matching(&self, criteria: &RelayCriteria) -> Result<Vec<RelayInfo>, RegistryError> {
        let relays = self.relays.read().await;
        
        let now = SystemTime::now();
        
        Ok(relays
            .values()
            .filter(|r| {
                // Check age if specified
                if let Some(max_age) = criteria.max_age {
                    if let Ok(age) = now.duration_since(r.last_seen) {
                        if age > max_age {
                            return false;
                        }
                    }
                }
                r.matches_criteria(criteria)
            })
            .cloned()
            .collect())
    }

    async fn update_health(&self, relay_id: &str, status: HealthStatus) -> Result<(), RegistryError> {
        let mut relays = self.relays.write().await;
        
        let relay = relays
            .get_mut(relay_id)
            .ok_or_else(|| RegistryError::NotFound(relay_id.to_string()))?;
        
        relay.health_status = status;
        debug!("Updated relay {} health status to {:?}", relay_id, status);
        Ok(())
    }

    async fn update_last_seen(&self, relay_id: &str) -> Result<(), RegistryError> {
        let mut relays = self.relays.write().await;
        
        let relay = relays
            .get_mut(relay_id)
            .ok_or_else(|| RegistryError::NotFound(relay_id.to_string()))?;
        
        relay.last_seen = SystemTime::now();
        Ok(())
    }

    async fn update_bandwidth(&self, relay_id: &str, bandwidth: u64) -> Result<(), RegistryError> {
        let mut relays = self.relays.write().await;
        
        let relay = relays
            .get_mut(relay_id)
            .ok_or_else(|| RegistryError::NotFound(relay_id.to_string()))?;
        
        relay.bandwidth = bandwidth;
        Ok(())
    }

    async fn verify_ownership(&self, relay_id: &str) -> Result<bool, RegistryError> {
        let relays = self.relays.read().await;
        
        let relay = relays
            .get(relay_id)
            .ok_or_else(|| RegistryError::NotFound(relay_id.to_string()))?;
        
        relay.verify_ownership()
    }

    async fn count(&self) -> Result<usize, RegistryError> {
        let relays = self.relays.read().await;
        Ok(relays.len())
    }

    async fn healthy_count(&self) -> Result<usize, RegistryError> {
        let relays = self.relays.read().await;
        Ok(relays.values().filter(|r| r.health_status.is_usable()).count())
    }
}

/// Persistent JSON file registry
pub struct JsonFileRegistry {
    inner: InMemoryRegistry,
    file_path: PathBuf,
    auto_save: bool,
}

impl JsonFileRegistry {
    /// Create new file-backed registry
    pub async fn new(file_path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let file_path = file_path.as_ref().to_path_buf();
        
        // Load existing data if file exists
        let inner = if file_path.exists() {
            Self::load_from_file(&file_path).await?
        } else {
            InMemoryRegistry::new()
        };

        Ok(Self {
            inner,
            file_path,
            auto_save: true,
        })
    }

    /// Create without auto-save
    pub async fn without_auto_save(file_path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let mut registry = Self::new(file_path).await?;
        registry.auto_save = false;
        Ok(registry)
    }

    /// Load relays from file
    async fn load_from_file(path: &Path) -> Result<InMemoryRegistry, RegistryError> {
        let content = fs::read_to_string(path).await?;
        let relays: Vec<RelayInfo> = serde_json::from_str(&content)?;
        info!("Loaded {} relays from {}", relays.len(), path.display());
        Ok(InMemoryRegistry::with_relays(relays))
    }

    /// Save relays to file
    pub async fn save(&self) -> Result<(), RegistryError> {
        let relays = self.inner.list_relays().await?;
        let content = serde_json::to_string_pretty(&relays)?;
        
        // Write to temp file first for atomicity
        let temp_path = self.file_path.with_extension("tmp");
        fs::write(&temp_path, content).await?;
        fs::rename(&temp_path, &self.file_path).await?;
        
        debug!("Saved {} relays to {}", relays.len(), self.file_path.display());
        Ok(())
    }

    /// Force save even if auto-save is disabled
    pub async fn force_save(&self) -> Result<(), RegistryError> {
        let relays = self.inner.list_relays().await?;
        let content = serde_json::to_string_pretty(&relays)?;
        
        let temp_path = self.file_path.with_extension("tmp");
        fs::write(&temp_path, content).await?;
        fs::rename(&temp_path, &self.file_path).await?;
        
        info!("Force saved {} relays to {}", relays.len(), self.file_path.display());
        Ok(())
    }
}

#[async_trait::async_trait]
impl RelayRegistry for JsonFileRegistry {
    async fn register(&self, relay: RelayInfo) -> Result<(), RegistryError> {
        self.inner.register(relay).await?;
        if self.auto_save {
            self.save().await?;
        }
        Ok(())
    }

    async fn unregister(&self, relay_id: &str) -> Result<(), RegistryError> {
        self.inner.unregister(relay_id).await?;
        if self.auto_save {
            self.save().await?;
        }
        Ok(())
    }

    async fn get_relay(&self, relay_id: &str) -> Result<RelayInfo, RegistryError> {
        self.inner.get_relay(relay_id).await
    }

    async fn get_relay_by_address(&self, address: &str) -> Result<RelayInfo, RegistryError> {
        self.inner.get_relay_by_address(address).await
    }

    async fn list_relays(&self) -> Result<Vec<RelayInfo>, RegistryError> {
        self.inner.list_relays().await
    }

    async fn list_matching(&self, criteria: &RelayCriteria) -> Result<Vec<RelayInfo>, RegistryError> {
        self.inner.list_matching(criteria).await
    }

    async fn update_health(&self, relay_id: &str, status: HealthStatus) -> Result<(), RegistryError> {
        self.inner.update_health(relay_id, status).await?;
        if self.auto_save {
            self.save().await?;
        }
        Ok(())
    }

    async fn update_last_seen(&self, relay_id: &str) -> Result<(), RegistryError> {
        self.inner.update_last_seen(relay_id).await?;
        if self.auto_save {
            self.save().await?;
        }
        Ok(())
    }

    async fn update_bandwidth(&self, relay_id: &str, bandwidth: u64) -> Result<(), RegistryError> {
        self.inner.update_bandwidth(relay_id, bandwidth).await?;
        if self.auto_save {
            self.save().await?;
        }
        Ok(())
    }

    async fn verify_ownership(&self, relay_id: &str) -> Result<bool, RegistryError> {
        self.inner.verify_ownership(relay_id).await
    }

    async fn count(&self) -> Result<usize, RegistryError> {
        self.inner.count().await
    }

    async fn healthy_count(&self) -> Result<usize, RegistryError> {
        self.inner.healthy_count().await
    }
}

/// Signed relay list for distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRelayList {
    /// List of relays
    pub relays: Vec<RelayInfo>,
    /// Timestamp when signed
    pub timestamp: SystemTime,
    /// Signature of the relay list
    pub signature: String,
    /// Authority public key
    pub authority_key: String,
}

impl SignedRelayList {
    /// Create new signed list
    pub fn new(relays: Vec<RelayInfo>) -> Self {
        Self {
            relays,
            timestamp: SystemTime::now(),
            signature: String::new(),
            authority_key: String::new(),
        }
    }

    /// Sign the relay list
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), RegistryError> {
        use ed25519_dalek::Signer;

        // Create canonical representation for signing (without signature)
        let mut to_sign = self.clone();
        to_sign.signature.clear();
        to_sign.authority_key.clear();
        
        let message = serde_json::to_vec(&to_sign)
            .map_err(|e| RegistryError::SerializationError(e))?;
        
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        
        let signature = signing_key.sign(&message);
        
        self.signature = BASE64.encode(signature.to_bytes());
        self.authority_key = BASE64.encode(signing_key.verifying_key().as_bytes());
        
        Ok(())
    }

    /// Verify the signature
    pub fn verify(&self) -> Result<bool, RegistryError> {
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        if self.signature.is_empty() || self.authority_key.is_empty() {
            return Ok(false);
        }

        // Decode authority key
        let pk_bytes = BASE64.decode(&self.authority_key)
            .map_err(|e| RegistryError::InvalidKey(format!("Invalid authority key: {}", e)))?;
        
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(&pk_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| RegistryError::InvalidKey(format!("Invalid verifying key: {:?}", e)))?;

        // Decode signature
        let sig_bytes = BASE64.decode(&self.signature)
            .map_err(|e| RegistryError::InvalidProof(format!("Invalid signature: {}", e)))?;
        
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // Create canonical representation
        let mut to_verify = self.clone();
        to_verify.signature.clear();
        to_verify.authority_key.clear();
        
        let message = serde_json::to_vec(&to_verify)
            .map_err(|e| RegistryError::SerializationError(e))?;

        match verifying_key.verify(&message, &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Registry rate limiter
pub struct RegistryRateLimiter {
    /// Request counts per client
    requests: Arc<RwLock<HashMap<String, Vec<SystemTime>>>>,
    /// Maximum requests per window
    max_requests: usize,
    /// Window duration
    window: Duration,
}

impl RegistryRateLimiter {
    /// Create new rate limiter
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    /// Check if request is allowed
    pub async fn check(&self, client_id: &str) -> Result<(), RegistryError> {
        let mut requests = self.requests.write().await;
        let now = SystemTime::now();
        
        let client_requests = requests.entry(client_id.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        client_requests.retain(|&time| {
            now.duration_since(time).unwrap_or(Duration::MAX) < self.window
        });
        
        if client_requests.len() >= self.max_requests {
            warn!("Rate limit exceeded for client {}", client_id);
            return Err(RegistryError::RateLimited);
        }
        
        client_requests.push(now);
        Ok(())
    }

    /// Clean up old entries
    pub async fn cleanup(&self) {
        let mut requests = self.requests.write().await;
        let now = SystemTime::now();
        
        requests.retain(|_, times| {
            times.retain(|&time| {
                now.duration_since(time).unwrap_or(Duration::MAX) < self.window
            });
            !times.is_empty()
        });
    }
}

impl Default for RegistryRateLimiter {
    fn default() -> Self {
        Self::new(100, Duration::from_secs(60)) // 100 requests per minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_registry() {
        let registry = InMemoryRegistry::new();
        
        // Register a relay
        let relay = RelayInfo::new("192.168.1.1:9001", "test_key", 1000000)
            .with_nickname("test_relay");
        
        registry.register(relay.clone()).await.unwrap();
        
        // Retrieve it
        let retrieved = registry.get_relay(&relay.id).await.unwrap();
        assert_eq!(retrieved.address, "192.168.1.1:9001");
        
        // Check count
        assert_eq!(registry.count().await.unwrap(), 1);
        
        // Unregister
        registry.unregister(&relay.id).await.unwrap();
        assert_eq!(registry.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_relay_criteria() {
        let relay = RelayInfo::new("192.168.1.1:9001", "test_key", 1000000)
            .with_security_level(SecurityLevel::Enhanced);
        
        // Should match enhanced criteria
        let criteria = RelayCriteria::new()
            .with_min_security_level(SecurityLevel::Enhanced)
            .require_healthy();
        
        assert!(relay.matches_criteria(&criteria));
        
        // Should not match maximum criteria
        let criteria_max = RelayCriteria::new()
            .with_min_security_level(SecurityLevel::Maximum);
        
        assert!(!relay.matches_criteria(&criteria_max));
    }

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_usable());
        assert!(HealthStatus::Degraded.is_usable());
        assert!(!HealthStatus::Offline.is_usable());
        assert!(!HealthStatus::Maintenance.is_usable());
        assert!(!HealthStatus::Banned.is_usable());
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RegistryRateLimiter::new(3, Duration::from_secs(60));
        
        // First 3 should succeed
        for _ in 0..3 {
            limiter.check("client1").await.unwrap();
        }
        
        // 4th should fail
        assert!(limiter.check("client1").await.is_err());
        
        // Different client should succeed
        limiter.check("client2").await.unwrap();
    }
}
