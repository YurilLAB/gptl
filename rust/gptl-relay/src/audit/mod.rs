//! Audit Logging with Tamper-Evident Records
//!
//! Implements secure audit logging inspired by financial and compliance systems:
//! - All authentication attempts logged
//! - Administrative actions audit trail
//! - Tamper-evident Merkle tree log structure
//! - Cryptographic chain of custody
//! - Structured JSON logging with signatures

use std::collections::VecDeque;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};

/// Audit logger with tamper-evident logging
#[derive(Debug)]
pub struct AuditLogger {
    /// Log storage
    storage: Arc<RwLock<LogStorage>>,
    /// Signing key for log entries
    signing_key: Vec<u8>,
    /// Maximum entries in memory
    max_memory_entries: usize,
    /// Minimum log level
    min_level: AuditLevel,
    /// Persistent storage path
    storage_path: Option<PathBuf>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(signing_key: Vec<u8>) -> Self {
        Self {
            storage: Arc::new(RwLock::new(LogStorage::new())),
            signing_key,
            max_memory_entries: 10000,
            min_level: AuditLevel::Info,
            storage_path: None,
        }
    }

    /// Set maximum in-memory entries
    pub fn with_max_memory_entries(mut self, max: usize) -> Self {
        self.max_memory_entries = max;
        self
    }

    /// Set minimum log level
    pub fn with_min_level(mut self, level: AuditLevel) -> Self {
        self.min_level = level;
        self
    }

    /// Enable persistent storage
    pub fn with_persistent_storage(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Enable tamper-evident logging (alias for backward compatibility)
    pub fn with_tamper_evident(self, _enabled: bool) -> Self {
        // Tamper-evident logging is always enabled
        self
    }

    /// Load logs from persistent storage
    pub async fn load_from_storage(&self) -> crate::Result<()> {
        if let Some(ref path) = self.storage_path {
            if path.exists() {
                let contents = tokio::fs::read_to_string(path).await
                    .map_err(|e| crate::RelayError::AuditError(format!("Failed to read log file: {}", e)))?;

                let log: TamperEvidentLog = serde_json::from_str(&contents)
                    .map_err(|e| crate::RelayError::AuditError(format!("Failed to parse log file: {}", e)))?;

                let mut storage = self.storage.write().await;
                storage.entries = log.entries;
                storage.merkle_root = log.merkle_root;
                storage.next_sequence = log.entry_count;
                storage.update_merkle_tree();
            }
        }
        Ok(())
    }

    /// Save logs to persistent storage
    pub async fn save_to_storage(&self) -> crate::Result<()> {
        if let Some(ref path) = self.storage_path {
            let log = self.export_tamper_evident_log().await;
            let json = serde_json::to_string_pretty(&log)
                .map_err(|e| crate::RelayError::AuditError(format!("Failed to serialize logs: {}", e)))?;

            // Ensure parent directory exists
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| crate::RelayError::AuditError(format!("Failed to create log directory: {}", e)))?;
            }

            tokio::fs::write(path, json).await
                .map_err(|e| crate::RelayError::AuditError(format!("Failed to write log file: {}", e)))?;
        }
        Ok(())
    }

    /// Log an authentication attempt
    pub async fn log_auth_attempt(
        &self,
        event: AuthEvent,
        context: &crate::SecurityContext,
    ) -> crate::Result<LogEntry> {
        let entry = SecurityEvent::AuthAttempt(event);
        self.log(entry, context).await
    }

    /// Log an administrative action
    pub async fn log_admin_action(
        &self,
        event: AdminEvent,
        context: &crate::SecurityContext,
    ) -> crate::Result<LogEntry> {
        let entry = SecurityEvent::AdminAction(event);
        self.log(entry, context).await
    }

    /// Log a security event
    pub async fn log_security_event(
        &self,
        event: SecurityEventType,
        context: &crate::SecurityContext,
    ) -> crate::Result<LogEntry> {
        let entry = SecurityEvent::SecurityEvent(event);
        self.log(entry, context).await
    }

    /// Log a session event
    pub async fn log_session_event(
        &self,
        event: SessionEvent,
        context: &crate::SecurityContext,
    ) -> crate::Result<LogEntry> {
        let entry = SecurityEvent::SessionEvent(event);
        self.log(entry, context).await
    }

    /// Core logging function
    async fn log(
        &self,
        event: SecurityEvent,
        context: &crate::SecurityContext,
    ) -> crate::Result<LogEntry> {
        // Check log level
        if event.level() < self.min_level {
            return Err(crate::RelayError::AuditError(
                "Event below minimum log level".to_string()
            ));
        }

        let mut storage = self.storage.write().await;

        // Create entry
        let sequence = storage.next_sequence();
        let timestamp = Utc::now();
        
        // Get previous hash for chain
        let previous_hash = storage.last_hash()
            .unwrap_or_else(|| vec![0u8; 32]);

        // Create entry data
        let entry_data = LogEntryData {
            sequence,
            timestamp,
            event,
            context: LogContext::from(context),
            previous_hash: previous_hash.clone(),
        };

        // Calculate hash
        let hash = Self::calculate_hash(&entry_data);

        // Sign entry
        let signature = Self::sign_entry(&hash, &self.signing_key);

        // Create final entry
        let entry = LogEntry {
            sequence,
            timestamp,
            hash: hex_encode(&hash),
            previous_hash: hex_encode(&previous_hash),
            signature: hex_encode(&signature),
            data: entry_data,
        };

        // Store entry
        storage.add_entry(entry.clone());

        // Update Merkle tree
        storage.update_merkle_tree();

        // Trim old entries if needed
        if storage.entries.len() > self.max_memory_entries {
            storage.archive_old_entries();
        }

        // Release lock before saving
        drop(storage);

        // Save to persistent storage if configured
        if self.storage_path.is_some() {
            let _ = self.save_to_storage().await;
        }

        Ok(entry)
    }

    /// Verify log integrity
    pub async fn verify_integrity(&self) -> IntegrityReport {
        let storage = self.storage.read().await;
        let mut report = IntegrityReport {
            total_entries: storage.entries.len(),
            valid_entries: 0,
            invalid_entries: 0,
            broken_chain_at: None,
            last_verified_sequence: 0,
        };

        // After `archive_old_entries()` drops the oldest entries, the first
        // remaining entry's sequence is no longer 0.  Anchor `expected_sequence`
        // to that first sequence so verify_integrity() doesn't immediately
        // flag broken_chain_at: 0 on every well-formed archived log.
        let mut expected_sequence = storage.entries.front().map(|e| e.sequence).unwrap_or(0);
        let mut last_hash: Option<Vec<u8>> = None;

        for entry in &storage.entries {
            // Check sequence
            if entry.sequence != expected_sequence {
                report.broken_chain_at = Some(expected_sequence);
                break;
            }

            // Verify hash chain
            if let Some(ref last) = last_hash {
                let prev_hash = hex_decode(&entry.previous_hash).unwrap_or_default();
                if prev_hash != *last {
                    report.broken_chain_at = Some(entry.sequence);
                    break;
                }
            }

            // Verify entry hash
            let calculated_hash = Self::calculate_hash(&entry.data);
            let stored_hash = hex_decode(&entry.hash).unwrap_or_default();
            
            if calculated_hash != stored_hash {
                report.invalid_entries += 1;
            } else {
                report.valid_entries += 1;
            }

            // Verify signature
            let signature_valid = Self::verify_signature(
                &calculated_hash,
                &hex_decode(&entry.signature).unwrap_or_default(),
                &self.signing_key,
            );

            if !signature_valid {
                report.invalid_entries += 1;
            }

            last_hash = Some(stored_hash);
            expected_sequence += 1;
            report.last_verified_sequence = entry.sequence;
        }

        report
    }

    /// Get log entries with filtering
    pub async fn query(
        &self,
        filter: LogFilter,
    ) -> Vec<LogEntry> {
        let storage = self.storage.read().await;
        
        storage.entries.iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect()
    }

    /// Get a specific entry by sequence
    pub async fn get_entry(&self, sequence: u64) -> Option<LogEntry> {
        let storage = self.storage.read().await;
        storage.entries.iter()
            .find(|e| e.sequence == sequence)
            .cloned()
    }

    /// Get entries in a range
    pub async fn get_range(&self, start: u64, end: u64) -> Vec<LogEntry> {
        let storage = self.storage.read().await;
        
        storage.entries.iter()
            .filter(|e| e.sequence >= start && e.sequence <= end)
            .cloned()
            .collect()
    }

    /// Export tamper-evident log
    pub async fn export_tamper_evident_log(&self) -> TamperEvidentLog {
        let storage = self.storage.read().await;
        
        TamperEvidentLog {
            entries: storage.entries.clone(),
            merkle_root: storage.merkle_root.clone(),
            exported_at: Utc::now(),
            entry_count: storage.entries.len() as u64,
        }
    }

    /// Get current Merkle root
    pub async fn get_merkle_root(&self) -> Option<String> {
        let storage = self.storage.read().await;
        storage.merkle_root.clone()
    }

    /// Calculate hash of entry data
    fn calculate_hash(data: &LogEntryData) -> Vec<u8> {
        let json = serde_json::to_string(data).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Sign an entry
    fn sign_entry(hash: &[u8], key: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(hash);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify signature
    fn verify_signature(hash: &[u8], signature: &[u8], key: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(hash);
        
        mac.verify_slice(signature).is_ok()
    }
}

impl Default for AuditLogger {
    /// Build an audit logger with a freshly generated random 32-byte HMAC key.
    ///
    /// The previous implementation used `vec![0u8; 32]` — meaning any
    /// code path that constructed `AuditLogger::default()` silently produced
    /// HMAC signatures with an all-zero key, and any attacker aware of the
    /// default could forge log entries whose `verify_integrity()` would
    /// return true.  We now refuse to start with a predictable key.
    fn default() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::new(key)
    }
}

/// Log storage with Merkle tree
#[derive(Debug)]
struct LogStorage {
    entries: VecDeque<LogEntry>,
    merkle_tree: Vec<Vec<u8>>,
    merkle_root: Option<String>,
    next_sequence: u64,
}

impl LogStorage {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            merkle_tree: Vec::new(),
            merkle_root: None,
            next_sequence: 0,
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.next_sequence;
        self.next_sequence += 1;
        seq
    }

    fn add_entry(&mut self, entry: LogEntry) {
        self.entries.push_back(entry);
    }

    fn last_hash(&self) -> Option<Vec<u8>> {
        self.entries.back()
            .map(|e| hex_decode(&e.hash).unwrap_or_default())
    }

    fn update_merkle_tree(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        // RFC 6962 Certificate-Transparency-style domain separation:
        //   leaf hash     = SHA256(0x00 || entry.hash)
        //   internal node = SHA256(0x01 || left || right)
        //
        // Without these prefixes, the raw 32-byte concatenation of two leaf
        // hashes is indistinguishable from a single internal-node input,
        // letting an attacker forge a membership proof for a non-existent
        // log entry by constructing an internal node whose preimage looks
        // like a leaf.
        let mut hashes: Vec<Vec<u8>> = self.entries.iter()
            .map(|e| {
                let raw = hex_decode(&e.hash).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update([0x00u8]);
                hasher.update(&raw);
                hasher.finalize().to_vec()
            })
            .collect();

        // Build tree bottom-up
        self.merkle_tree = hashes.clone();

        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in hashes.chunks(2) {
                let (left, right) = if chunk.len() == 2 {
                    (chunk[0].as_slice(), chunk[1].as_slice())
                } else {
                    // Last odd node is duplicated.
                    (chunk[0].as_slice(), chunk[0].as_slice())
                };

                let mut hasher = Sha256::new();
                hasher.update([0x01u8]);
                hasher.update(left);
                hasher.update(right);
                next_level.push(hasher.finalize().to_vec());
            }

            self.merkle_tree.extend(next_level.clone());
            hashes = next_level;
        }

        if let Some(root) = hashes.first() {
            self.merkle_root = Some(hex_encode(root));
        }
    }

    fn archive_old_entries(&mut self) {
        // In production, this would write to persistent storage
        // For now, just keep recent entries
        while self.entries.len() > 1000 {
            self.entries.pop_front();
        }
    }
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SecurityEvent {
    AuthAttempt(AuthEvent),
    AdminAction(AdminEvent),
    SecurityEvent(SecurityEventType),
    SessionEvent(SessionEvent),
}

impl SecurityEvent {
    /// Get log level for this event
    pub fn level(&self) -> AuditLevel {
        match self {
            SecurityEvent::AuthAttempt(e) => e.level(),
            SecurityEvent::AdminAction(_) => AuditLevel::Info,
            SecurityEvent::SecurityEvent(e) => e.level(),
            SecurityEvent::SessionEvent(_) => AuditLevel::Debug,
        }
    }
}

/// Authentication event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub auth_method: String,
    pub success: bool,
    pub failure_reason: Option<String>,
    pub mfa_used: bool,
    pub client_cert: bool,
}

impl AuthEvent {
    pub fn level(&self) -> AuditLevel {
        if self.success {
            AuditLevel::Info
        } else {
            AuditLevel::Warning
        }
    }
}

/// Administrative action event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEvent {
    pub action: String,
    pub target: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub admin_user_id: String,
}

/// Security event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventType {
    pub event_type: String,
    pub severity: SecuritySeverity,
    pub description: String,
    pub details: Option<serde_json::Value>,
}

impl SecurityEventType {
    pub fn level(&self) -> AuditLevel {
        match self.severity {
            SecuritySeverity::Critical => AuditLevel::Critical,
            SecuritySeverity::High => AuditLevel::Error,
            SecuritySeverity::Medium => AuditLevel::Warning,
            SecuritySeverity::Low => AuditLevel::Info,
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Session event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    pub session_id: String,
    pub event_type: SessionEventType,
    pub user_id: String,
}

/// Session event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionEventType {
    Created,
    Refreshed,
    Revoked,
    Expired,
    BindingViolation,
}

/// Audit log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub hash: String,
    pub previous_hash: String,
    pub signature: String,
    pub data: LogEntryData,
}

/// Log entry data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntryData {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub event: SecurityEvent,
    pub context: LogContext,
    pub previous_hash: Vec<u8>,
}

/// Log context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogContext {
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub api_key_id: Option<String>,
    pub client_ip: String,
    pub client_fingerprint: Option<String>,
    pub request_id: String,
}

impl From<&crate::SecurityContext> for LogContext {
    fn from(ctx: &crate::SecurityContext) -> Self {
        Self {
            user_id: ctx.user_id.clone(),
            session_id: ctx.session_id.clone(),
            api_key_id: ctx.api_key_id.clone(),
            client_ip: ctx.client_ip.to_string(),
            client_fingerprint: ctx.client_fingerprint.clone(),
            request_id: ctx.request_id.clone(),
        }
    }
}

/// Log filter for querying
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub user_id: Option<String>,
    pub event_types: Vec<String>,
    pub min_level: Option<AuditLevel>,
}

impl LogFilter {
    pub fn matches(&self, entry: &LogEntry) -> bool {
        if let Some(start) = self.start_time {
            if entry.timestamp < start {
                return false;
            }
        }

        if let Some(end) = self.end_time {
            if entry.timestamp > end {
                return false;
            }
        }

        if let Some(ref user_id) = self.user_id {
            // Check context user_id first; fall back to event-level user_id
            // (e.g. when SecurityContext was constructed without a user_id but
            // the AuthEvent itself carries one).
            let in_context = entry.data.context.user_id.as_ref() == Some(user_id);
            let in_event = match &entry.data.event {
                SecurityEvent::AuthAttempt(e) => e.user_id.as_ref() == Some(user_id),
                _ => false,
            };
            if !in_context && !in_event {
                return false;
            }
        }

        if let Some(min_level) = self.min_level {
            if entry.data.event.level() < min_level {
                return false;
            }
        }

        true
    }
}

/// Integrity verification report
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub invalid_entries: usize,
    pub broken_chain_at: Option<u64>,
    pub last_verified_sequence: u64,
}

/// Tamper-evident log export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvidentLog {
    pub entries: VecDeque<LogEntry>,
    pub merkle_root: Option<String>,
    pub exported_at: DateTime<Utc>,
    pub entry_count: u64,
}

/// Helper functions
fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logging() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        let event = AuthEvent {
            user_id: Some("user123".to_string()),
            username: Some("testuser".to_string()),
            auth_method: "password+totp".to_string(),
            success: true,
            failure_reason: None,
            mfa_used: true,
            client_cert: false,
        };

        let entry = logger.log_auth_attempt(event, &ctx).await.unwrap();

        assert_eq!(entry.sequence, 0);
        assert!(!entry.hash.is_empty());
        assert!(!entry.signature.is_empty());
        assert_eq!(entry.previous_hash, "00".repeat(32));
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        // Log some events
        for i in 0..5 {
            let event = AuthEvent {
                user_id: Some(format!("user{}", i)),
                username: Some(format!("user{}", i)),
                auth_method: "password".to_string(),
                success: i % 2 == 0,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx).await.unwrap();
        }

        // Verify integrity
        let report = logger.verify_integrity().await;
        assert_eq!(report.total_entries, 5);
        assert_eq!(report.valid_entries, 5);
        assert!(report.broken_chain_at.is_none());
    }

    #[tokio::test]
    async fn test_integrity_verification_survives_archival() {
        // Regression: before fix, `verify_integrity()` anchored
        // `expected_sequence` to 0, so once `archive_old_entries()` dropped
        // the first entries, EVERY subsequent call reported
        // `broken_chain_at: Some(0)`.  Now it anchors to the first remaining
        // entry's sequence.
        //
        // Use a low max_memory_entries cap so archival fires quickly.
        let logger = AuditLogger::new(vec![1u8; 32]).with_max_memory_entries(50);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        for i in 0..1200usize {
            let event = AuthEvent {
                user_id: Some(format!("user{}", i)),
                username: Some(format!("user{}", i)),
                auth_method: "password".to_string(),
                success: true,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx).await.unwrap();
        }

        let report = logger.verify_integrity().await;
        assert!(report.total_entries > 0 && report.total_entries <= 1000,
            "archive must have trimmed; got total={}", report.total_entries);
        assert!(report.broken_chain_at.is_none(),
            "integrity must NOT flag a broken chain on a well-formed archived log; \
             got broken_chain_at={:?} valid={} invalid={}",
            report.broken_chain_at, report.valid_entries, report.invalid_entries);
    }

    #[tokio::test]
    async fn test_merkle_tree_generation() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        // Log multiple events
        for i in 0..10 {
            let event = AuthEvent {
                user_id: Some(format!("user{}", i)),
                username: Some(format!("user{}", i)),
                auth_method: "password".to_string(),
                success: true,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx).await.unwrap();
        }

        // Get Merkle root
        let root = logger.get_merkle_root().await;
        assert!(root.is_some());
        assert!(!root.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_log_filtering() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        // Log events for different users
        for i in 0..5 {
            let event = AuthEvent {
                user_id: Some(format!("user{}", i % 2)),
                username: Some(format!("user{}", i % 2)),
                auth_method: "password".to_string(),
                success: true,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx).await.unwrap();
        }

        // Filter by user
        let filter = LogFilter {
            user_id: Some("user0".to_string()),
            ..Default::default()
        };

        let filtered = logger.query(filter).await;
        assert_eq!(filtered.len(), 3); // user0, user0, user0
    }

    #[tokio::test]
    async fn test_persistent_storage() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.log");

        let logger = AuditLogger::new(vec![1u8; 32])
            .with_persistent_storage(&log_path);

        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        // Log some events
        for i in 0..3 {
            let event = AuthEvent {
                user_id: Some(format!("user{}", i)),
                username: Some(format!("user{}", i)),
                auth_method: "password".to_string(),
                success: true,
                failure_reason: None,
                mfa_used: false,
                client_cert: false,
            };
            logger.log_auth_attempt(event, &ctx).await.unwrap();
        }

        // Verify file was created
        assert!(log_path.exists());

        // Create new logger and load
        let logger2 = AuditLogger::new(vec![1u8; 32])
            .with_persistent_storage(&log_path);

        logger2.load_from_storage().await.unwrap();

        // Verify entries were loaded
        let entries = logger2.query(LogFilter::default()).await;
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_security_event_logging() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        let event = SecurityEventType {
            event_type: "suspicious_activity".to_string(),
            severity: SecuritySeverity::High,
            description: "Multiple failed login attempts".to_string(),
            details: None,
        };

        let entry = logger.log_security_event(event, &ctx).await.unwrap();
        assert_eq!(entry.sequence, 0);
    }

    #[tokio::test]
    async fn test_admin_action_logging() {
        let logger = AuditLogger::new(vec![1u8; 32]);
        let ctx = crate::SecurityContext::new("192.168.1.1".parse().unwrap());

        let event = AdminEvent {
            action: "user_delete".to_string(),
            target: "user123".to_string(),
            old_value: Some("active".to_string()),
            new_value: Some("deleted".to_string()),
            admin_user_id: "admin1".to_string(),
        };

        let entry = logger.log_admin_action(event, &ctx).await.unwrap();
        assert_eq!(entry.sequence, 0);
    }

    #[test]
    fn test_log_filter() {
        let filter = LogFilter {
            user_id: Some("user123".to_string()),
            min_level: Some(AuditLevel::Warning),
            ..Default::default()
        };

        // This would test the filter against actual entries
        // For now just verify filter construction
        assert_eq!(filter.user_id, Some("user123".to_string()));
    }

    #[test]
    fn test_hex_encoding() {
        let data = vec![0x01, 0x02, 0x03, 0xff];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "010203ff");

        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_audit_level_ordering() {
        assert!(AuditLevel::Debug < AuditLevel::Info);
        assert!(AuditLevel::Info < AuditLevel::Warning);
        assert!(AuditLevel::Warning < AuditLevel::Error);
        assert!(AuditLevel::Error < AuditLevel::Critical);
    }
}
