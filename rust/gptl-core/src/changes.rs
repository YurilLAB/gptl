//! System Change Tracking Module
//!
//! Tracks all modifications GPTL makes to the system including:
//! - File modifications
//! - Registry changes (Windows)
//! - Firewall rules
//! - Service registrations
//! - Network namespaces
//! - User/group creation
//! - Permission changes
//! - Configuration files

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Categories of system changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChangeCategory {
    /// Network-related changes (firewall rules, ports, interfaces)
    Network,
    /// Security-related changes (sandboxing, permissions, ACLs)
    Security,
    /// Service-related changes (auto-start, systemd, Windows services)
    Service,
    /// Configuration file changes
    Configuration,
    /// System-level changes (sysctl, kernel params, registry)
    System,
    /// File system changes (create, modify, delete files)
    Filesystem,
    /// User and group modifications
    UserGroup,
}

impl std::fmt::Display for ChangeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeCategory::Network => write!(f, "Network"),
            ChangeCategory::Security => write!(f, "Security"),
            ChangeCategory::Service => write!(f, "Service"),
            ChangeCategory::Configuration => write!(f, "Configuration"),
            ChangeCategory::System => write!(f, "System"),
            ChangeCategory::Filesystem => write!(f, "Filesystem"),
            ChangeCategory::UserGroup => write!(f, "UserGroup"),
        }
    }
}

impl ChangeCategory {
    /// Parse category from string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "network" => Some(ChangeCategory::Network),
            "security" => Some(ChangeCategory::Security),
            "service" => Some(ChangeCategory::Service),
            "configuration" | "config" => Some(ChangeCategory::Configuration),
            "system" => Some(ChangeCategory::System),
            "filesystem" | "file" => Some(ChangeCategory::Filesystem),
            "usergroup" | "user" | "group" => Some(ChangeCategory::UserGroup),
            _ => None,
        }
    }
}

/// Status of a system change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeStatus {
    /// Change is pending execution
    Pending,
    /// Change was successfully applied
    Applied,
    /// Change failed to apply
    Failed,
    /// Change was rolled back
    RolledBack,
    /// Rollback failed
    RollbackFailed,
}

impl std::fmt::Display for ChangeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeStatus::Pending => write!(f, "Pending"),
            ChangeStatus::Applied => write!(f, "Applied"),
            ChangeStatus::Failed => write!(f, "Failed"),
            ChangeStatus::RolledBack => write!(f, "RolledBack"),
            ChangeStatus::RollbackFailed => write!(f, "RollbackFailed"),
        }
    }
}

/// Platform-specific change details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformDetails {
    /// Windows-specific details
    Windows {
        /// Registry keys modified
        registry_keys: Vec<String>,
        /// Windows services affected
        services: Vec<String>,
        /// Windows firewall rules
        firewall_rules: Vec<String>,
    },
    /// Linux-specific details
    Linux {
        /// Systemd units modified
        systemd_units: Vec<String>,
        /// Sysctl parameters changed
        sysctl_params: Vec<String>,
        /// Network namespaces created
        net_namespaces: Vec<String>,
        /// iptables rules
        iptables_rules: Vec<String>,
    },
    /// macOS-specific details
    MacOS {
        /// Launchd plists modified
        launchd_plists: Vec<String>,
        /// PF firewall rules
        pf_rules: Vec<String>,
    },
    /// Platform-agnostic
    Generic,
}

/// Represents a single system change made by GPTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemChange {
    /// Unique identifier for this change
    pub id: Uuid,
    /// Timestamp when change was made
    pub timestamp: DateTime<Utc>,
    /// Category of the change
    pub category: ChangeCategory,
    /// Human-readable description
    pub description: String,
    /// The command or action that was executed
    pub command_or_action: String,
    /// Command to rollback this change (if available)
    pub rollback_command: Option<String>,
    /// Files affected by this change
    pub files_affected: Vec<PathBuf>,
    /// Whether this change requires admin/root privileges
    pub requires_admin: bool,
    /// Current status of the change
    pub status: ChangeStatus,
    /// Platform-specific details
    pub platform_details: PlatformDetails,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Error message if change failed
    pub error_message: Option<String>,
    /// Component that made the change
    pub component: String,
    /// Version of GPTL that made the change
    pub gptl_version: String,
}

impl SystemChange {
    /// Create a new system change
    pub fn new(
        category: ChangeCategory,
        description: impl Into<String>,
        command_or_action: impl Into<String>,
        component: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category,
            description: description.into(),
            command_or_action: command_or_action.into(),
            rollback_command: None,
            files_affected: Vec::new(),
            requires_admin: false,
            status: ChangeStatus::Pending,
            platform_details: PlatformDetails::Generic,
            metadata: HashMap::new(),
            error_message: None,
            component: component.into(),
            gptl_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Set the rollback command
    pub fn with_rollback(mut self, command: impl Into<String>) -> Self {
        self.rollback_command = Some(command.into());
        self
    }

    /// Add affected files
    pub fn with_files(mut self, files: Vec<PathBuf>) -> Self {
        self.files_affected = files;
        self
    }

    /// Mark as requiring admin
    pub fn with_admin(mut self) -> Self {
        self.requires_admin = true;
        self
    }

    /// Set platform details
    pub fn with_platform_details(mut self, details: PlatformDetails) -> Self {
        self.platform_details = details;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Mark as applied successfully
    pub fn mark_applied(&mut self) {
        self.status = ChangeStatus::Applied;
    }

    /// Mark as failed
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = ChangeStatus::Failed;
        self.error_message = Some(error.into());
    }

    /// Mark as rolled back
    pub fn mark_rolled_back(&mut self) {
        self.status = ChangeStatus::RolledBack;
    }

    /// Mark as rollback failed
    pub fn mark_rollback_failed(&mut self, error: impl Into<String>) {
        self.status = ChangeStatus::RollbackFailed;
        self.error_message = Some(error.into());
    }
}

/// Configuration for the change tracker
#[derive(Debug, Clone)]
pub struct ChangeTrackerConfig {
    /// Path to store change log files
    pub log_dir: PathBuf,
    /// Maximum number of changes to keep in memory
    pub max_memory_entries: usize,
    /// Whether to persist changes to disk
    pub persist_to_disk: bool,
    /// Maximum age of changes to retain (in days)
    pub retention_days: u32,
    /// Whether to track file system changes
    pub track_filesystem: bool,
    /// Whether to track registry changes (Windows)
    pub track_registry: bool,
}

impl Default for ChangeTrackerConfig {
    fn default() -> Self {
        let log_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gptl")
            .join("changes");

        Self {
            log_dir,
            max_memory_entries: 1000,
            persist_to_disk: true,
            retention_days: 90,
            track_filesystem: true,
            track_registry: cfg!(windows),
        }
    }
}

/// Error types for change tracking operations
#[derive(Debug, thiserror::Error)]
pub enum ChangeTrackerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Change not found: {0}")]
    ChangeNotFound(Uuid),
    #[error("Rollback not available for change: {0}")]
    RollbackNotAvailable(Uuid),
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
    #[error("Change already rolled back: {0}")]
    AlreadyRolledBack(Uuid),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Filters for querying changes
#[derive(Debug, Clone, Default)]
pub struct ChangeFilter {
    /// Filter by category
    pub category: Option<ChangeCategory>,
    /// Filter by status
    pub status: Option<ChangeStatus>,
    /// Filter by start date (inclusive)
    pub since: Option<DateTime<Utc>>,
    /// Filter by end date (inclusive)
    pub until: Option<DateTime<Utc>>,
    /// Filter by component
    pub component: Option<String>,
    /// Filter by requiring admin
    pub requires_admin: Option<bool>,
    /// Search in description
    pub search: Option<String>,
}

impl ChangeFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by category
    pub fn with_category(mut self, category: ChangeCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Filter by status
    pub fn with_status(mut self, status: ChangeStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Filter by start date
    pub fn with_since(mut self, since: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self
    }

    /// Filter by end date
    pub fn with_until(mut self, until: DateTime<Utc>) -> Self {
        self.until = Some(until);
        self
    }

    /// Filter by component
    pub fn with_component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Filter by admin requirement
    pub fn with_requires_admin(mut self, requires_admin: bool) -> Self {
        self.requires_admin = Some(requires_admin);
        self
    }

    /// Search in description
    pub fn with_search(mut self, search: impl Into<String>) -> Self {
        self.search = Some(search.into());
        self
    }

    /// Check if a change matches this filter
    pub fn matches(&self, change: &SystemChange) -> bool {
        if let Some(category) = self.category {
            if change.category != category {
                return false;
            }
        }

        if let Some(status) = self.status {
            if change.status != status {
                return false;
            }
        }

        if let Some(since) = self.since {
            if change.timestamp < since {
                return false;
            }
        }

        if let Some(until) = self.until {
            if change.timestamp > until {
                return false;
            }
        }

        if let Some(ref component) = self.component {
            if !change.component.eq_ignore_ascii_case(component) {
                return false;
            }
        }

        if let Some(requires_admin) = self.requires_admin {
            if change.requires_admin != requires_admin {
                return false;
            }
        }

        if let Some(ref search) = self.search {
            let search_lower = search.to_lowercase();
            if !change.description.to_lowercase().contains(&search_lower)
                && !change.command_or_action.to_lowercase().contains(&search_lower)
            {
                return false;
            }
        }

        true
    }
}

/// Main change tracker for logging and managing system changes
pub struct ChangeTracker {
    config: ChangeTrackerConfig,
    changes: Arc<RwLock<Vec<SystemChange>>>,
}

impl ChangeTracker {
    /// Create a new change tracker with default config
    pub fn new() -> Self {
        Self::with_config(ChangeTrackerConfig::default())
    }

    /// Create a new change tracker with custom config
    pub fn with_config(config: ChangeTrackerConfig) -> Self {
        Self {
            config,
            changes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initialize the change tracker
    pub async fn initialize(&self) -> Result<(), ChangeTrackerError> {
        if self.config.persist_to_disk {
            fs::create_dir_all(&self.config.log_dir).await?;
            self.load_changes().await?;
        }
        Ok(())
    }

    /// Record a new system change
    pub async fn record(&self, change: SystemChange) -> Result<Uuid, ChangeTrackerError> {
        let id = change.id;
        
        // Add to in-memory storage
        {
            let mut changes = self.changes.write().await;
            changes.push(change);
            
            // Trim if exceeding max memory entries
            if changes.len() > self.config.max_memory_entries {
                let to_remove = changes.len() - self.config.max_memory_entries;
                // Remove oldest entries (at the beginning)
                changes.drain(0..to_remove);
            }
        }

        // Persist to disk if enabled
        if self.config.persist_to_disk {
            self.persist_changes().await?;
        }

        Ok(id)
    }

    /// Record a change and mark it as applied
    pub async fn record_applied(&self, mut change: SystemChange) -> Result<Uuid, ChangeTrackerError> {
        change.mark_applied();
        self.record(change).await
    }

    /// Get all changes
    pub async fn get_all(&self) -> Vec<SystemChange> {
        self.changes.read().await.clone()
    }

    /// Get a specific change by ID
    pub async fn get(&self, id: Uuid) -> Option<SystemChange> {
        self.changes.read().await.iter().find(|c| c.id == id).cloned()
    }

    /// Get changes matching a filter
    pub async fn get_filtered(&self, filter: &ChangeFilter) -> Vec<SystemChange> {
        self.changes
            .read()
            .await
            .iter()
            .filter(|c| filter.matches(c))
            .cloned()
            .collect()
    }

    /// Rollback a specific change
    pub async fn rollback(&self, id: Uuid) -> Result<(), ChangeTrackerError> {
        let mut change = self
            .get(id)
            .await
            .ok_or(ChangeTrackerError::ChangeNotFound(id))?;

        // Check if already rolled back
        if change.status == ChangeStatus::RolledBack {
            return Err(ChangeTrackerError::AlreadyRolledBack(id));
        }

        // Get rollback command
        let rollback_cmd = change
            .rollback_command
            .clone()
            .ok_or(ChangeTrackerError::RollbackNotAvailable(id))?;

        // Execute rollback
        match self.execute_rollback(&rollback_cmd).await {
            Ok(_) => {
                change.mark_rolled_back();
                self.update_change(change).await?;
                Ok(())
            }
            Err(e) => {
                change.mark_rollback_failed(e.to_string());
                self.update_change(change).await?;
                Err(ChangeTrackerError::RollbackFailed(e.to_string()))
            }
        }
    }

    /// Export changes to JSON
    pub async fn export_json(&self, filter: &ChangeFilter) -> Result<String, ChangeTrackerError> {
        let changes = self.get_filtered(filter).await;
        Ok(serde_json::to_string_pretty(&changes)?)
    }

    /// Export changes to CSV
    pub async fn export_csv(&self, filter: &ChangeFilter) -> Result<String, ChangeTrackerError> {
        let changes = self.get_filtered(filter).await;
        
        let mut csv = String::new();
        csv.push_str("id,timestamp,category,status,description,command,requires_admin,component,gptl_version\n");
        
        for change in changes {
            csv.push_str(&format!(
                "{},{},{},{},\"{}\",\"{}\",{},{},{}\n",
                change.id,
                change.timestamp.to_rfc3339(),
                change.category,
                change.status,
                change.description.replace('"', "\"\""),
                change.command_or_action.replace('"', "\"\""),
                change.requires_admin,
                change.component,
                change.gptl_version
            ));
        }
        
        Ok(csv)
    }

    /// Get summary statistics
    pub async fn get_statistics(&self) -> ChangeStatistics {
        let changes = self.changes.read().await;
        
        let mut stats = ChangeStatistics { total_changes: changes.len(), ..Default::default() };
        
        for change in changes.iter() {
            match change.status {
                ChangeStatus::Applied => stats.applied_count += 1,
                ChangeStatus::Failed => stats.failed_count += 1,
                ChangeStatus::RolledBack => stats.rolled_back_count += 1,
                ChangeStatus::RollbackFailed => stats.rollback_failed_count += 1,
                ChangeStatus::Pending => stats.pending_count += 1,
            }
            
            *stats.by_category.entry(change.category).or_insert(0) += 1;
        }
        
        stats
    }

    /// Clear all changes (use with caution)
    pub async fn clear(&self) -> Result<(), ChangeTrackerError> {
        let mut changes = self.changes.write().await;
        changes.clear();
        
        if self.config.persist_to_disk {
            self.persist_changes().await?;
        }
        
        Ok(())
    }

    /// Update an existing change
    async fn update_change(&self, updated: SystemChange) -> Result<(), ChangeTrackerError> {
        let mut changes = self.changes.write().await;
        
        if let Some(idx) = changes.iter().position(|c| c.id == updated.id) {
            changes[idx] = updated;
            
            if self.config.persist_to_disk {
                drop(changes);
                self.persist_changes().await?;
            }
        }
        
        Ok(())
    }

    /// Execute rollback command
    async fn execute_rollback(&self, command: &str) -> Result<(), ChangeTrackerError> {
        // Parse and execute the rollback command
        // This is platform-specific and depends on the type of change
        
        #[cfg(windows)]
        {
            use std::process::Command;
            
            let output = Command::new("powershell")
                .args(["-Command", command])
                .output()
                .map_err(|e| ChangeTrackerError::RollbackFailed(e.to_string()))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ChangeTrackerError::RollbackFailed(stderr.to_string()));
            }
        }
        
        #[cfg(unix)]
        {
            use std::process::Command;
            
            let output = Command::new("sh")
                .args(["-c", command])
                .output()
                .map_err(|e| ChangeTrackerError::RollbackFailed(e.to_string()))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ChangeTrackerError::RollbackFailed(stderr.to_string()));
            }
        }
        
        Ok(())
    }

    /// Persist changes to disk
    async fn persist_changes(&self) -> Result<(), ChangeTrackerError> {
        let changes = self.changes.read().await;
        let data = serde_json::to_string(&*changes)?;
        
        let file_path = self.config.log_dir.join("changes.json");
        fs::write(&file_path, data).await?;
        
        Ok(())
    }

    /// Load changes from disk
    async fn load_changes(&self) -> Result<(), ChangeTrackerError> {
        let file_path = self.config.log_dir.join("changes.json");
        
        if file_path.exists() {
            let data = fs::read_to_string(&file_path).await?;
            let loaded: Vec<SystemChange> = serde_json::from_str(&data)?;
            
            let mut changes = self.changes.write().await;
            *changes = loaded;
        }
        
        Ok(())
    }
}

impl Default for ChangeTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about system changes
#[derive(Debug, Clone, Default)]
pub struct ChangeStatistics {
    pub total_changes: usize,
    pub applied_count: usize,
    pub failed_count: usize,
    pub rolled_back_count: usize,
    pub rollback_failed_count: usize,
    pub pending_count: usize,
    pub by_category: HashMap<ChangeCategory, usize>,
}

/// Builder for common system changes
pub struct ChangeBuilder;

impl ChangeBuilder {
    /// Create a firewall rule change
    pub fn firewall_rule(
        description: impl Into<String>,
        rule_spec: impl Into<String>,
    ) -> SystemChange {
        SystemChange::new(
            ChangeCategory::Network,
            description,
            rule_spec,
            "network/firewall",
        )
        .with_admin()
    }

    /// Create a file modification change
    pub fn file_modification(
        description: impl Into<String>,
        file_path: PathBuf,
        operation: impl Into<String>,
    ) -> SystemChange {
        SystemChange::new(
            ChangeCategory::Filesystem,
            description,
            operation,
            "filesystem",
        )
        .with_files(vec![file_path])
    }

    /// Create a registry modification change (Windows)
    pub fn registry_change(
        description: impl Into<String>,
        key: impl Into<String>,
        operation: impl Into<String>,
    ) -> SystemChange {
        let key_str = key.into();
        SystemChange::new(
            ChangeCategory::System,
            description,
            operation,
            "system/registry",
        )
        .with_admin()
        .with_platform_details(PlatformDetails::Windows {
            registry_keys: vec![key_str],
            services: vec![],
            firewall_rules: vec![],
        })
    }

    /// Create a service registration change
    pub fn service_registration(
        description: impl Into<String>,
        service_name: impl Into<String>,
        operation: impl Into<String>,
    ) -> SystemChange {
        let service_name_str = service_name.into();
        SystemChange::new(
            ChangeCategory::Service,
            description,
            operation,
            "service/manager",
        )
        .with_admin()
        .with_platform_details(PlatformDetails::Windows {
            registry_keys: vec![],
            services: vec![service_name_str],
            firewall_rules: vec![],
        })
    }

    /// Create a network namespace change (Linux)
    pub fn network_namespace(
        description: impl Into<String>,
        namespace: impl Into<String>,
        operation: impl Into<String>,
    ) -> SystemChange {
        let ns_str = namespace.into();
        SystemChange::new(
            ChangeCategory::Network,
            description,
            operation,
            "network/namespace",
        )
        .with_admin()
        .with_platform_details(PlatformDetails::Linux {
            systemd_units: vec![],
            sysctl_params: vec![],
            net_namespaces: vec![ns_str],
            iptables_rules: vec![],
        })
    }

    /// Create a user/group change
    pub fn user_group(
        description: impl Into<String>,
        _name: impl Into<String>,
        operation: impl Into<String>,
    ) -> SystemChange {
        SystemChange::new(
            ChangeCategory::UserGroup,
            description,
            operation,
            "user/group",
        )
        .with_admin()
    }

    /// Create a permission change
    pub fn permission_change(
        description: impl Into<String>,
        _target: impl Into<String>,
        operation: impl Into<String>,
    ) -> SystemChange {
        SystemChange::new(
            ChangeCategory::Security,
            description,
            operation,
            "security/permissions",
        )
        .with_admin()
    }

    /// Create a configuration file change
    pub fn config_file(
        description: impl Into<String>,
        file_path: PathBuf,
        operation: impl Into<String>,
    ) -> SystemChange {
        SystemChange::new(
            ChangeCategory::Configuration,
            description,
            operation,
            "configuration",
        )
        .with_files(vec![file_path])
    }

    /// Create a sysctl/kernel parameter change (Linux)
    pub fn sysctl_change(
        description: impl Into<String>,
        param: impl Into<String>,
        value: impl Into<String>,
    ) -> SystemChange {
        let param_str: String = param.into();
        let value_str: String = value.into();
        let param_clone = param_str.clone();
        SystemChange::new(
            ChangeCategory::System,
            description,
            format!("sysctl -w {}={}", param_str, value_str),
            "system/sysctl",
        )
        .with_admin()
        .with_platform_details(PlatformDetails::Linux {
            systemd_units: vec![],
            sysctl_params: vec![param_str],
            net_namespaces: vec![],
            iptables_rules: vec![],
        })
        .with_rollback(format!("sysctl -w {}=default", param_clone))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_change_tracker() {
        // Use in-memory only config for tests
        let config = ChangeTrackerConfig {
            persist_to_disk: false,
            ..Default::default()
        };
        let tracker = ChangeTracker::with_config(config);

        let change = SystemChange::new(
            ChangeCategory::Network,
            "Test firewall rule",
            "netsh advfirewall add rule...",
            "test",
        );

        let id = tracker.record(change).await.unwrap();

        let retrieved = tracker.get(id).await;
        assert!(retrieved.is_some());

        let filter = ChangeFilter::new().with_category(ChangeCategory::Network);
        let filtered = tracker.get_filtered(&filter).await;
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_change_filter() {
        let change = SystemChange::new(
            ChangeCategory::Network,
            "Test change",
            "test command",
            "test",
        )
        .with_admin();

        let filter = ChangeFilter::new()
            .with_category(ChangeCategory::Network)
            .with_requires_admin(true);

        assert!(filter.matches(&change));

        let filter2 = ChangeFilter::new().with_category(ChangeCategory::Security);
        assert!(!filter2.matches(&change));
    }

    #[test]
    fn test_change_builder() {
        let change = ChangeBuilder::firewall_rule(
            "Allow port 8080",
            "netsh advfirewall firewall add rule...",
        );

        assert_eq!(change.category, ChangeCategory::Network);
        assert!(change.requires_admin);
    }
}
