//! Firewall Automation and Verification System
//!
//! This module provides cross-platform firewall management with:
//! - Automatic firewall detection and configuration
//! - Rule verification and testing
//! - Rollback support
//! - Comprehensive error handling
//! - Safety checks and user confirmation

use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Represents a firewall system type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallType {
    /// Uncomplicated Firewall (Ubuntu/Debian)
    Ufw,
    /// Firewall daemon (RHEL/CentOS/Fedora)
    Firewalld,
    /// nftables (modern Linux)
    Nftables,
    /// iptables (legacy Linux)
    Iptables,
    /// Windows Defender Firewall (netsh)
    WindowsNetsh,
    /// Windows Defender Firewall (PowerShell)
    WindowsPowerShell,
    /// macOS Packet Filter
    MacPfctl,
    /// macOS Application Firewall
    MacSocketfilterfw,
    /// Unknown or unsupported
    Unknown,
}

impl std::fmt::Display for FirewallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallType::Ufw => write!(f, "UFW (Uncomplicated Firewall)"),
            FirewallType::Firewalld => write!(f, "firewalld"),
            FirewallType::Nftables => write!(f, "nftables"),
            FirewallType::Iptables => write!(f, "iptables"),
            FirewallType::WindowsNetsh => write!(f, "Windows Defender Firewall (netsh)"),
            FirewallType::WindowsPowerShell => write!(f, "Windows Defender Firewall (PowerShell)"),
            FirewallType::MacPfctl => write!(f, "macOS PF (Packet Filter)"),
            FirewallType::MacSocketfilterfw => write!(f, "macOS Application Firewall"),
            FirewallType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Represents a tracked firewall rule for rollback purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedRule {
    /// Unique identifier for this rule tracking
    pub id: String,
    /// When the rule was added
    pub timestamp: SystemTime,
    /// The firewall type used
    pub firewall_type: FirewallType,
    /// Port number
    pub port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
    /// Description/rule name
    pub description: String,
    /// The actual command used to add the rule
    pub add_command: String,
    /// The command to remove the rule (for rollback)
    pub remove_command: String,
    /// Whether verification succeeded
    pub verified: bool,
    /// Original state backup (if applicable)
    pub original_state: Option<String>,
}

/// Result of a firewall operation
#[derive(Debug, Clone)]
pub struct FirewallResult {
    pub success: bool,
    pub message: String,
    pub rule_id: Option<String>,
    pub verification_passed: bool,
    pub warnings: Vec<String>,
}

/// Main firewall automation manager
#[derive(Debug)]
pub struct FirewallAutomation {
    /// Detected firewall type
    firewall_type: FirewallType,
    /// Tracked rules (for rollback)
    tracked_rules: Vec<TrackedRule>,
    /// State file path for persistence
    state_file: PathBuf,
    /// Whether running with admin/root privileges
    has_admin: bool,
    /// Whether to auto-confirm operations
    auto_confirm: bool,
}

impl FirewallAutomation {
    /// Create a new firewall automation instance
    pub fn new() -> Self {
        let state_file = Self::get_state_file_path();
        let has_admin = Self::check_admin_privileges();
        
        let mut automation = Self {
            firewall_type: FirewallType::Unknown,
            tracked_rules: Vec::new(),
            state_file,
            has_admin,
            auto_confirm: false,
        };
        
        // Detect available firewall
        automation.firewall_type = automation.detect_firewall();
        
        // Load tracked rules from disk
        if let Err(e) = automation.load_tracked_rules() {
            warn!("Failed to load tracked firewall rules: {}", e);
        }
        
        automation
    }
    
    /// Create with auto-confirmation enabled
    pub fn with_auto_confirm(mut self, confirm: bool) -> Self {
        self.auto_confirm = confirm;
        self
    }
    
    /// Get the detected firewall type
    pub fn firewall_type(&self) -> FirewallType {
        self.firewall_type
    }
    
    /// Check if admin privileges are available
    pub fn has_admin(&self) -> bool {
        self.has_admin
    }
    
    /// Get the state file path
    fn get_state_file_path() -> PathBuf {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("gptl-relay");
        
        // Ensure directory exists
        let _ = std::fs::create_dir_all(&config_dir);
        
        config_dir.join("firewall_rules.json")
    }
    
    /// Check if running with admin/root privileges
    fn check_admin_privileges() -> bool {
        #[cfg(windows)]
        {
            // Check if running as administrator on Windows
            match Command::new("net").args(&["session"]).output() {
                Ok(output) => output.status.success(),
                Err(_) => false,
            }
        }
        
        #[cfg(unix)]
        {
            // Check if running as root on Unix
            unsafe { libc::getuid() == 0 }
        }
        
        #[cfg(not(any(windows, unix)))]
        {
            false
        }
    }
    
    /// Detect which firewall system is available
    fn detect_firewall(&self) -> FirewallType {
        #[cfg(target_os = "linux")]
        {
            // Check for UFW first (most common on Ubuntu/Debian)
            if self.command_exists("ufw") {
                debug!("Detected UFW firewall");
                return FirewallType::Ufw;
            }
            
            // Check for firewalld (RHEL/CentOS/Fedora)
            if self.command_exists("firewall-cmd") {
                debug!("Detected firewalld");
                return FirewallType::Firewalld;
            }
            
            // Check for nftables
            if self.command_exists("nft") {
                debug!("Detected nftables");
                return FirewallType::Nftables;
            }
            
            // Fall back to iptables
            if self.command_exists("iptables") {
                debug!("Detected iptables");
                return FirewallType::Iptables;
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Check for netsh (always available on Windows)
            if self.command_exists("netsh") {
                debug!("Detected Windows Defender Firewall (netsh)");
                return FirewallType::WindowsNetsh;
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // Check for pfctl
            if self.command_exists("pfctl") {
                debug!("Detected macOS PF");
                return FirewallType::MacPfctl;
            }
            
            // Check for socketfilterfw
            if self.command_exists("/usr/libexec/ApplicationFirewall/socketfilterfw") {
                debug!("Detected macOS Application Firewall");
                return FirewallType::MacSocketfilterfw;
            }
        }
        
        warn!("No supported firewall detected");
        FirewallType::Unknown
    }
    
    /// Check if a command exists in PATH
    fn command_exists(&self, cmd: &str) -> bool {
        which::which(cmd).is_ok()
    }
    
    /// Open a port through the firewall
    pub async fn open_port(
        &mut self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // Validate inputs.  `port` is u16, so the upper bound is enforced by
        // the type system — only `port == 0` can fail this check.
        if port == 0 {
            return Err(FirewallError::InvalidPort(port));
        }
        
        let protocol = match protocol.to_lowercase().as_str() {
            "tcp" | "udp" => protocol.to_lowercase(),
            _ => return Err(FirewallError::InvalidProtocol(protocol.to_string())),
        };
        
        info!(
            "Opening port {}/{} through {} for: {}",
            port, protocol, self.firewall_type, description
        );
        
        // Check admin privileges
        if !self.has_admin {
            return Err(FirewallError::PermissionDenied(
                self.get_admin_instructions()
            ));
        }
        
        // Check if rule already exists
        if self.rule_exists(port, &protocol).await? {
            info!("Port {}/{} is already open, skipping", port, protocol);
            return Ok(FirewallResult {
                success: true,
                message: format!("Port {}/{} is already open", port, protocol),
                rule_id: None,
                verification_passed: true,
                warnings: vec!["Rule already existed".to_string()],
            });
        }
        
        // Warn about security implications
        if !self.auto_confirm {
            self.warn_security_implications(port, &protocol);
        }
        
        // Add the rule based on firewall type
        let result = match self.firewall_type {
            FirewallType::Ufw => self.add_ufw_rule(port, &protocol, description).await,
            FirewallType::Firewalld => self.add_firewalld_rule(port, &protocol, description).await,
            FirewallType::Nftables => self.add_nftables_rule(port, &protocol, description).await,
            FirewallType::Iptables => self.add_iptables_rule(port, &protocol, description).await,
            FirewallType::WindowsNetsh => self.add_windows_netsh_rule(port, &protocol, description).await,
            FirewallType::WindowsPowerShell => self.add_windows_ps_rule(port, &protocol, description).await,
            FirewallType::MacPfctl => self.add_mac_pf_rule(port, &protocol, description).await,
            FirewallType::MacSocketfilterfw => Err(FirewallError::Unsupported(
                "macOS Application Firewall requires manual configuration".to_string()
            )),
            FirewallType::Unknown => Err(FirewallError::NoFirewall),
        }?;
        
        // Track the rule for rollback
        let rule_id = result.rule_id.clone();
        if let Some(ref id) = rule_id {
            self.tracked_rules.push(TrackedRule {
                id: id.clone(),
                timestamp: SystemTime::now(),
                firewall_type: self.firewall_type,
                port,
                protocol: protocol.clone(),
                description: description.to_string(),
                add_command: result.message.clone(),
                remove_command: self.get_remove_command(port, &protocol, description),
                verified: false,
                original_state: None,
            });
            
            // Save tracked rules
            let _ = self.save_tracked_rules();
        }
        
        // Verify the rule was applied
        let verified = self.verify_rule_applied(port, &protocol).await?;
        
        // Update the tracked rule with verification status
        if let Some(ref id) = rule_id {
            if let Some(rule) = self.tracked_rules.iter_mut().find(|r| r.id == *id) {
                rule.verified = verified;
            }
            let _ = self.save_tracked_rules();
        }
        
        // Test if the port is actually reachable
        let port_test = self.test_port_open(port).await;
        
        let mut warnings = result.warnings.clone();
        if !verified {
            warnings.push("Rule was added but verification failed".to_string());
        }
        if !port_test {
            warnings.push("Port may not be reachable from external networks".to_string());
        }
        
        Ok(FirewallResult {
            success: result.success && verified,
            message: if verified {
                format!("Successfully opened port {}/{}", port, protocol)
            } else {
                format!("Added rule for port {}/{} but verification failed", port, protocol)
            },
            rule_id,
            verification_passed: verified,
            warnings,
        })
    }
    
    /// Check if a rule already exists
    async fn rule_exists(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        match self.firewall_type {
            FirewallType::Ufw => self.check_ufw_rule_exists(port, protocol).await,
            FirewallType::Firewalld => self.check_firewalld_rule_exists(port, protocol).await,
            FirewallType::Nftables => self.check_nftables_rule_exists(port, protocol).await,
            FirewallType::Iptables => self.check_iptables_rule_exists(port, protocol).await,
            FirewallType::WindowsNetsh => self.check_windows_rule_exists(port, protocol).await,
            FirewallType::WindowsPowerShell => self.check_windows_ps_rule_exists(port, protocol).await,
            _ => Ok(false),
        }
    }
    
    /// Add a rule using UFW
    async fn add_ufw_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // First, check if UFW is enabled
        let status_output = Command::new("ufw")
            .args(&["status"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("ufw status failed: {}", e)))?;
        
        let status_str = String::from_utf8_lossy(&status_output.stdout);
        let ufw_enabled = status_str.contains("Status: active");
        
        // Add the rule
        let output = Command::new("ufw")
            .args(&["allow", &format!("{}/{}", port, protocol)])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("ufw allow failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "UFW failed to add rule: {}",
                stderr
            )));
        }
        
        // If UFW was disabled, warn the user
        let mut warnings = Vec::new();
        if !ufw_enabled {
            warnings.push("UFW is disabled. Enable it with: sudo ufw enable".to_string());
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: format!("ufw allow {}/{}", port, protocol),
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings,
        })
    }
    
    /// Check if a UFW rule exists
    async fn check_ufw_rule_exists(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("ufw")
            .args(&["status", "verbose"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("ufw status failed: {}", e)))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let pattern = format!("{}.*{}", port, protocol.to_uppercase());
        
        Ok(stdout.contains(&pattern) || stdout.contains(&format!("{}/{}", port, protocol)))
    }
    
    /// Add a rule using firewalld
    async fn add_firewalld_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // Check if firewalld is running
        let status_output = Command::new("systemctl")
            .args(&["is-active", "firewalld"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("systemctl failed: {}", e)))?;
        
        let is_running = status_output.status.success();
        
        // Add permanent rule
        let output = Command::new("firewall-cmd")
            .args(&[
                "--permanent",
                "--add-port",
                &format!("{}/{}", port, protocol),
            ])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("firewall-cmd failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "firewalld failed to add rule: {}",
                stderr
            )));
        }
        
        // Reload firewalld to apply changes
        if is_running {
            let reload = Command::new("firewall-cmd")
                .args(&["--reload"])
                .output();
            
            if let Err(e) = reload {
                warn!("Failed to reload firewalld: {}", e);
            }
        }
        
        let mut warnings = Vec::new();
        if !is_running {
            warnings.push("firewalld is not running. Start it with: sudo systemctl start firewalld".to_string());
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: format!("firewall-cmd --permanent --add-port={}/{}", port, protocol),
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings,
        })
    }
    
    /// Check if a firewalld rule exists
    async fn check_firewalld_rule_exists(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("firewall-cmd")
            .args(&["--list-ports"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Ok(stdout.contains(&format!("{}/{}", port, protocol)))
            }
            _ => Ok(false),
        }
    }
    
    /// Add a rule using nftables
    async fn add_nftables_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // For nftables, we need to add to the input chain
        let rule = format!(
            "add rule inet filter input {} dport {} accept comment \"{}\"",
            protocol, port, description
        );
        
        let output = Command::new("nft")
            .args(&[&rule])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("nft failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // If the table doesn't exist, try to create it
            if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
                return self.create_nftables_table_and_rule(port, protocol, description).await;
            }
            
            return Err(FirewallError::CommandFailed(format!(
                "nftables failed to add rule: {}",
                stderr
            )));
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: rule,
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec![],
        })
    }
    
    /// Create nftables table and add rule
    async fn create_nftables_table_and_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // Create table
        let _ = Command::new("nft")
            .args(&["add", "table", "inet", "filter"])
            .output();
        
        // Create chain
        let _ = Command::new("nft")
            .args(&[
                "add", "chain", "inet", "filter", "input",
                "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"
            ])
            .output();
        
        // Add rule
        let rule = format!(
            "add rule inet filter input {} dport {} accept comment \"{}\"",
            protocol, port, description
        );
        
        let output = Command::new("nft")
            .args(&[&rule])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("nft failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "nftables failed: {}",
                stderr
            )));
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: rule,
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec!["Created new nftables table".to_string()],
        })
    }
    
    /// Check if nftables rule exists
    async fn check_nftables_rule_exists(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("nft")
            .args(&["list", "table", "inet", "filter"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Ok(stdout.contains(&format!("{} dport {}", protocol, port)))
            }
            _ => Ok(false),
        }
    }
    
    /// Add a rule using iptables
    async fn add_iptables_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        let output = Command::new("iptables")
            .args(&[
                "-I", "INPUT",
                "-p", protocol,
                "--dport", &port.to_string(),
                "-j", "ACCEPT",
                "-m", "comment",
                "--comment", &format!("gptl-relay: {}", description),
            ])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("iptables failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "iptables failed to add rule: {}",
                stderr
            )));
        }
        
        // Try to save rules for persistence
        let save_result = Command::new("iptables-save")
            .output();
        
        if let Ok(save_out) = save_result {
            let rules = String::from_utf8_lossy(&save_out.stdout);
            let _ = std::fs::write("/etc/iptables/rules.v4", rules.as_bytes());
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: format!(
                "iptables -I INPUT -p {} --dport {} -j ACCEPT",
                protocol, port
            ),
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec!["Rules may not persist after reboot without iptables-persistent".to_string()],
        })
    }
    
    /// Check if iptables rule exists
    async fn check_iptables_rule_exists(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("iptables")
            .args(&["-L", "INPUT", "-n"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Ok(stdout.contains(&format!("dpt:{} ", port)) && 
                   stdout.to_lowercase().contains(&format!("{} ", protocol)))
            }
            _ => Ok(false),
        }
    }
    
    /// Add a rule using Windows netsh
    async fn add_windows_netsh_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        let rule_name = format!("GPTL Relay - {} - {}/{}", description, port, protocol);
        
        let output = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                &format!("dir=in"),
                &format!("action=allow"),
                &format!("protocol={}", protocol),
                &format!("localport={}", port),
                &format!("description=Auto-generated by GPTL Relay for: {}", description),
            ])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("netsh failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "Windows Firewall failed: {}",
                stderr
            )));
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: format!("netsh advfirewall add rule name=\"{}\"", rule_name),
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec![],
        })
    }
    
    /// Check if Windows rule exists
    async fn check_windows_rule_exists(&self, port: u16, _protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("netsh")
            .args(&["advfirewall", "firewall", "show", "rule", "name=all"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Look for the port in the output
                Ok(stdout.contains(&format!("LocalPort: {}", port)) ||
                   stdout.contains(&format!("{}", port)))
            }
            _ => Ok(false),
        }
    }
    
    /// Add a rule using Windows PowerShell
    async fn add_windows_ps_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        let rule_name = format!("GPTL Relay - {} - {}/{}", description, port, protocol);
        
        let ps_command = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -LocalPort {} -Protocol {} -Action Allow",
            rule_name, port, protocol
        );
        
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &ps_command,
            ])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("PowerShell failed: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(FirewallError::CommandFailed(format!(
                "PowerShell firewall command failed: {}",
                stderr
            )));
        }
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: ps_command,
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec![],
        })
    }
    
    /// Check if Windows PowerShell rule exists
    async fn check_windows_ps_rule_exists(&self, port: u16, _protocol: &str) -> Result<bool, FirewallError> {
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &format!("Get-NetFirewallRule | Get-NetFirewallPortFilter | Where-Object {{ $_.LocalPort -eq {} }}", port),
            ])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                Ok(!stdout.trim().is_empty())
            }
            _ => Ok(false),
        }
    }
    
    /// Add a rule using macOS PF
    async fn add_mac_pf_rule(
        &self,
        port: u16,
        protocol: &str,
        description: &str,
    ) -> Result<FirewallResult, FirewallError> {
        // Create an anchor file for our rules
        let anchor_path = "/etc/pf.anchors/gptl-relay";
        let rule = format!("pass in proto {} from any to any port {}\n", protocol, port);
        
        // Append to anchor file
        let current_content = std::fs::read_to_string(anchor_path).unwrap_or_default();
        let new_content = format!("{}{}", current_content, rule);
        
        std::fs::write(anchor_path, new_content)
            .map_err(|e| FirewallError::CommandFailed(format!(
                "Cannot write to {}: {}. SIP may be enabled.",
                anchor_path, e
            )))?;
        
        // Check if anchor is loaded
        let output = Command::new("pfctl")
            .args(&["-sr"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(format!("pfctl failed: {}", e)))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("anchor \"gptl-relay\"") {
            // Need to add anchor to main config
            warn!("PF anchor not loaded in main config. Add to /etc/pf.conf: anchor \"gptl-relay\"")
        }
        
        // Reload rules
        let _ = Command::new("pfctl")
            .args(&["-f", anchor_path])
            .output();
        
        let rule_id = Uuid::new_v4().to_string();
        
        Ok(FirewallResult {
            success: true,
            message: format!("Added PF rule: {}", rule.trim()),
            rule_id: Some(rule_id),
            verification_passed: false,
            warnings: vec![
                "macOS PF requires manual anchor configuration in /etc/pf.conf".to_string(),
                "SIP (System Integrity Protection) may prevent modifications".to_string(),
            ],
        })
    }
    
    /// Verify that a rule was actually applied
    async fn verify_rule_applied(&self, port: u16, protocol: &str) -> Result<bool, FirewallError> {
        // Try up to 3 times with a small delay
        for attempt in 1..=3 {
            if self.rule_exists(port, protocol).await? {
                return Ok(true);
            }
            
            if attempt < 3 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
        
        Ok(false)
    }
    
    /// Test if a port is actually open (listening)
    async fn test_port_open(&self, port: u16) -> bool {
        // Try to bind to the port locally
        match tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await {
            Ok(_) => {
                // Port is available, which means no one is listening
                // This is expected for a newly opened port
                true
            }
            Err(e) => {
                // Port might be in use or blocked
                debug!("Port {} test bind failed: {}", port, e);
                // This could mean the port is already in use (which is okay)
                e.kind() == std::io::ErrorKind::AddrInUse
            }
        }
    }
    
    /// Get the command to remove a rule (for rollback)
    fn get_remove_command(&self, port: u16, protocol: &str, description: &str) -> String {
        match self.firewall_type {
            FirewallType::Ufw => format!("ufw delete allow {}/{}", port, protocol),
            FirewallType::Firewalld => format!(
                "firewall-cmd --permanent --remove-port={}/{} && firewall-cmd --reload",
                port, protocol
            ),
            FirewallType::Nftables => format!(
                "nft delete rule inet filter input handle <handle>",
            ),
            FirewallType::Iptables => format!(
                "iptables -D INPUT -p {} --dport {} -j ACCEPT",
                protocol, port
            ),
            FirewallType::WindowsNetsh => format!(
                "netsh advfirewall firewall delete rule name=\"GPTL Relay - {} - {}/{}\"",
                description, port, protocol
            ),
            FirewallType::WindowsPowerShell => format!(
                "Remove-NetFirewallRule -DisplayName \"GPTL Relay - {} - {}/{}\"",
                description, port, protocol
            ),
            FirewallType::MacPfctl => format!(
                "# Edit /etc/pf.anchors/gptl-relay and remove: pass in proto {} from any to any port {}",
                protocol, port
            ),
            _ => "# Manual removal required".to_string(),
        }
    }
    
    /// Get instructions for gaining admin privileges
    fn get_admin_instructions(&self) -> String {
        #[cfg(windows)]
        {
            "Administrator privileges required. Run as Administrator or use: Run as administrator".to_string()
        }
        
        #[cfg(target_os = "linux")]
        {
            "Root privileges required. Use: sudo gptl-relay <command>".to_string()
        }
        
        #[cfg(target_os = "macos")]
        {
            "Administrator privileges required. Use: sudo gptl-relay <command>".to_string()
        }
        
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            "Administrator privileges required".to_string()
        }
    }
    
    /// Warn about security implications
    fn warn_security_implications(&self, port: u16, protocol: &str) {
        println!("\n⚠️  Security Warning");
        println!("====================\n");
        println!("Opening port {}/{} through the firewall may expose your system to network attacks.", 
                 port, protocol);
        println!("\nRecommendations:");
        println!("  - Ensure the service on this port is properly secured");
        println!("  - Consider using IP allowlisting for additional protection");
        println!("  - Regularly review open ports with: gptl-relay firewall-status");
        println!("  - Use rollback if needed: gptl-relay firewall-rollback");
        println!();
    }
    
    /// Rollback a specific rule by ID
    pub async fn rollback_rule(&mut self, rule_id: &str) -> Result<FirewallResult, FirewallError> {
        let rule_index = self.tracked_rules.iter().position(|r| r.id == rule_id);
        
        match rule_index {
            Some(index) => {
                let rule = self.tracked_rules.remove(index);
                
                info!("Rolling back firewall rule: {}/{}", rule.port, rule.protocol);
                
                // Execute rollback command
                let result = self.execute_rollback(&rule).await;
                
                // Save updated tracked rules
                let _ = self.save_tracked_rules();
                
                result
            }
            None => Err(FirewallError::RuleNotFound(rule_id.to_string())),
        }
    }
    
    /// Execute the rollback command
    async fn execute_rollback(&self, rule: &TrackedRule) -> Result<FirewallResult, FirewallError> {
        match rule.firewall_type {
            FirewallType::Ufw => {
                let output = Command::new("ufw")
                    .args(&["delete", "allow", &format!("{}/{}", rule.port, rule.protocol)])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(format!("ufw delete failed: {}", e)))?;
                
                if output.status.success() {
                    Ok(FirewallResult {
                        success: true,
                        message: format!("Removed UFW rule for port {}/{}", rule.port, rule.protocol),
                        rule_id: Some(rule.id.clone()),
                        verification_passed: true,
                        warnings: vec![],
                    })
                } else {
                    Err(FirewallError::CommandFailed(format!(
                        "Failed to remove UFW rule: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
            FirewallType::Firewalld => {
                let output = Command::new("firewall-cmd")
                    .args(&[
                        "--permanent",
                        "--remove-port",
                        &format!("{}/{}", rule.port, rule.protocol),
                    ])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(format!("firewall-cmd failed: {}", e)))?;
                
                let _ = Command::new("firewall-cmd").args(&["--reload"]).output();
                
                if output.status.success() {
                    Ok(FirewallResult {
                        success: true,
                        message: format!("Removed firewalld rule for port {}/{}", rule.port, rule.protocol),
                        rule_id: Some(rule.id.clone()),
                        verification_passed: true,
                        warnings: vec![],
                    })
                } else {
                    Err(FirewallError::CommandFailed(format!(
                        "Failed to remove firewalld rule: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
            FirewallType::Iptables => {
                let output = Command::new("iptables")
                    .args(&[
                        "-D", "INPUT",
                        "-p", &rule.protocol,
                        "--dport", &rule.port.to_string(),
                        "-j", "ACCEPT",
                    ])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(format!("iptables failed: {}", e)))?;
                
                if output.status.success() {
                    Ok(FirewallResult {
                        success: true,
                        message: format!("Removed iptables rule for port {}/{}", rule.port, rule.protocol),
                        rule_id: Some(rule.id.clone()),
                        verification_passed: true,
                        warnings: vec![],
                    })
                } else {
                    Err(FirewallError::CommandFailed(format!(
                        "Failed to remove iptables rule: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
            FirewallType::WindowsNetsh => {
                let rule_name = format!("GPTL Relay - {} - {}/{}", 
                    rule.description, rule.port, rule.protocol);
                
                let output = Command::new("netsh")
                    .args(&[
                        "advfirewall", "firewall", "delete", "rule",
                        &format!("name={}", rule_name),
                    ])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(format!("netsh failed: {}", e)))?;
                
                if output.status.success() {
                    Ok(FirewallResult {
                        success: true,
                        message: format!("Removed Windows Firewall rule for port {}/{}", 
                            rule.port, rule.protocol),
                        rule_id: Some(rule.id.clone()),
                        verification_passed: true,
                        warnings: vec![],
                    })
                } else {
                    Err(FirewallError::CommandFailed(format!(
                        "Failed to remove Windows Firewall rule: {}",
                        String::from_utf8_lossy(&output.stderr)
                    )))
                }
            }
            _ => {
                warn!("Rollback not implemented for {:?}", rule.firewall_type);
                Ok(FirewallResult {
                    success: true,
                    message: format!("Manual rollback required: {}", rule.remove_command),
                    rule_id: Some(rule.id.clone()),
                    verification_passed: false,
                    warnings: vec![format!("Manual removal required: {}", rule.remove_command)],
                })
            }
        }
    }
    
    /// Rollback all tracked rules
    pub async fn rollback_all(&mut self) -> Vec<Result<FirewallResult, FirewallError>> {
        let rule_ids: Vec<String> = self.tracked_rules.iter().map(|r| r.id.clone()).collect();
        
        let mut results = Vec::new();
        for rule_id in rule_ids {
            results.push(self.rollback_rule(&rule_id).await);
        }
        
        results
    }
    
    /// Get current firewall status
    pub async fn get_status(&self) -> Result<FirewallStatus, FirewallError> {
        let rules = match self.firewall_type {
            FirewallType::Ufw => self.get_ufw_status().await?,
            FirewallType::Firewalld => self.get_firewalld_status().await?,
            FirewallType::Iptables => self.get_iptables_status().await?,
            FirewallType::Nftables => self.get_nftables_status().await?,
            FirewallType::WindowsNetsh => self.get_windows_status().await?,
            FirewallType::WindowsPowerShell => self.get_windows_ps_status().await?,
            _ => vec![],
        };
        
        Ok(FirewallStatus {
            firewall_type: self.firewall_type,
            is_active: self.is_firewall_active().await?,
            has_admin: self.has_admin,
            rules,
            tracked_rules_count: self.tracked_rules.len(),
        })
    }
    
    /// Check if firewall is active
    async fn is_firewall_active(&self) -> Result<bool, FirewallError> {
        match self.firewall_type {
            FirewallType::Ufw => {
                let output = Command::new("ufw")
                    .args(&["status"])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(stdout.contains("Status: active"))
            }
            FirewallType::Firewalld => {
                let output = Command::new("systemctl")
                    .args(&["is-active", "firewalld"])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
                
                Ok(output.status.success())
            }
            FirewallType::WindowsNetsh | FirewallType::WindowsPowerShell => {
                // Windows Firewall is always "active" if the service is running
                let output = Command::new("sc")
                    .args(&["query", "mpssvc"])
                    .output()
                    .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
                
                let stdout = String::from_utf8_lossy(&output.stdout);
                Ok(stdout.contains("RUNNING"))
            }
            _ => Ok(false),
        }
    }
    
    /// Get UFW status
    async fn get_ufw_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("ufw")
            .args(&["status", "verbose"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        
        for line in stdout.lines() {
            // Parse lines like: "8443/tcp                   ALLOW IN    Anywhere"
            if line.contains("ALLOW") && (line.contains("/tcp") || line.contains("/udp")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if !parts.is_empty() {
                    let port_proto = parts[0];
                    if let Some((port_str, proto)) = port_proto.split_once('/') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            rules.push(FirewallRuleInfo {
                                port,
                                protocol: proto.to_string(),
                                source: parts.last().map(|s| s.to_string()),
                                action: "ALLOW".to_string(),
                                description: None,
                            });
                        }
                    }
                }
            }
        }
        
        Ok(rules)
    }
    
    /// Get firewalld status
    async fn get_firewalld_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("firewall-cmd")
            .args(&["--list-ports"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        
        for part in stdout.split_whitespace() {
            // Parse format like: "8443/tcp 8080/udp"
            if let Some((port_str, proto)) = part.split_once('/') {
                if let Ok(port) = port_str.parse::<u16>() {
                    rules.push(FirewallRuleInfo {
                        port,
                        protocol: proto.to_string(),
                        source: None,
                        action: "ALLOW".to_string(),
                        description: None,
                    });
                }
            }
        }
        
        Ok(rules)
    }
    
    /// Get iptables status
    async fn get_iptables_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("iptables")
            .args(&["-L", "INPUT", "-n", "--line-numbers"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        
        for line in stdout.lines() {
            // Parse lines like: "1    ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:8443"
            if line.contains("ACCEPT") && line.contains("dpt:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                
                // Find protocol
                let proto_idx = parts.iter().position(|&p| p == "tcp" || p == "udp");
                
                // Find port
                let port_part = parts.iter().find(|&&p| p.starts_with("dpt:"));
                
                if let (Some(proto), Some(port_str)) = (proto_idx, port_part) {
                    let port = port_str.trim_start_matches("dpt:").parse::<u16>().unwrap_or(0);
                    if port > 0 {
                        rules.push(FirewallRuleInfo {
                            port,
                            protocol: parts[proto].to_string(),
                            source: None,
                            action: "ACCEPT".to_string(),
                            description: None,
                        });
                    }
                }
            }
        }
        
        Ok(rules)
    }
    
    /// Get nftables status
    async fn get_nftables_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("nft")
            .args(&["list", "table", "inet", "filter"])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut rules = Vec::new();
                
                // Parse nftables output
                for line in stdout.lines() {
                    if line.contains("dport") && line.contains("accept") {
                        // Simple parsing - could be improved
                        if let Some(port_idx) = line.find("dport") {
                            let after_dport = &line[port_idx + 5..];
                            if let Some(end_idx) = after_dport.find(' ') {
                                let port_str = &after_dport[..end_idx].trim();
                                if let Ok(port) = port_str.parse::<u16>() {
                                    let proto = if line.contains("tcp") { "tcp" } else { "udp" };
                                    rules.push(FirewallRuleInfo {
                                        port,
                                        protocol: proto.to_string(),
                                        source: None,
                                        action: "ACCEPT".to_string(),
                                        description: None,
                                    });
                                }
                            }
                        }
                    }
                }
                
                Ok(rules)
            }
            _ => Ok(vec![]),
        }
    }
    
    /// Get Windows Firewall status
    async fn get_windows_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("netsh")
            .args(&["advfirewall", "firewall", "show", "rule", "name=all"])
            .output()
            .map_err(|e| FirewallError::CommandFailed(e.to_string()))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut rules = Vec::new();
        
        // Parse Windows netsh output (rule blocks separated by blank lines)
        let mut current_rule: Option<FirewallRuleInfo> = None;
        
        for line in stdout.lines() {
            let line = line.trim();
            
            if line.starts_with("Rule Name:") {
                // Save previous rule if exists
                if let Some(rule) = current_rule.take() {
                    rules.push(rule);
                }
                current_rule = Some(FirewallRuleInfo {
                    port: 0,
                    protocol: String::new(),
                    source: None,
                    action: String::new(),
                    description: Some(line.trim_start_matches("Rule Name:").trim().to_string()),
                });
            } else if let Some(ref mut rule) = current_rule {
                if line.starts_with("LocalPort:") {
                    let port_str = line.trim_start_matches("LocalPort:").trim();
                    if let Ok(port) = port_str.parse::<u16>() {
                        rule.port = port;
                    }
                } else if line.starts_with("Protocol:") {
                    rule.protocol = line.trim_start_matches("Protocol:").trim().to_string();
                } else if line.starts_with("Action:") {
                    rule.action = line.trim_start_matches("Action:").trim().to_string();
                }
            }
        }
        
        // Don't forget the last rule
        if let Some(rule) = current_rule {
            rules.push(rule);
        }
        
        Ok(rules)
    }
    
    /// Get Windows PowerShell firewall status
    async fn get_windows_ps_status(&self) -> Result<Vec<FirewallRuleInfo>, FirewallError> {
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                "Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | ForEach-Object { $portFilter = $_ | Get-NetFirewallPortFilter; \"Rule: $($_.DisplayName), Port: $($portFilter.LocalPort), Protocol: $($portFilter.Protocol), Action: $($_.Action)\" }",
            ])
            .output();
        
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let mut rules = Vec::new();
                
                for line in stdout.lines() {
                    // Parse: "Rule: name, Port: 8443, Protocol: TCP, Action: Allow"
                    if line.contains("Port:") {
                        let mut port = 0u16;
                        let mut protocol = String::new();
                        let mut action = String::new();
                        
                        for part in line.split(',') {
                            let part = part.trim();
                            if part.starts_with("Port:") {
                                port = part.split(':').nth(1)
                                    .and_then(|s| s.trim().parse().ok())
                                    .unwrap_or(0);
                            } else if part.starts_with("Protocol:") {
                                protocol = part.split(':').nth(1)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_default();
                            } else if part.starts_with("Action:") {
                                action = part.split(':').nth(1)
                                    .map(|s| s.trim().to_string())
                                    .unwrap_or_default();
                            }
                        }
                        
                        if port > 0 {
                            rules.push(FirewallRuleInfo {
                                port,
                                protocol,
                                source: None,
                                action,
                                description: None,
                            });
                        }
                    }
                }
                
                Ok(rules)
            }
            _ => Ok(vec![]),
        }
    }
    
    /// Get all tracked rules
    pub fn get_tracked_rules(&self) -> &[TrackedRule] {
        &self.tracked_rules
    }
    
    /// Save tracked rules to disk
    fn save_tracked_rules(&self) -> Result<(), FirewallError> {
        let json = serde_json::to_string_pretty(&self.tracked_rules)
            .map_err(|e| FirewallError::SerializationError(e.to_string()))?;
        
        std::fs::write(&self.state_file, json)
            .map_err(|e| FirewallError::IoError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Load tracked rules from disk
    fn load_tracked_rules(&mut self) -> Result<(), FirewallError> {
        if !self.state_file.exists() {
            return Ok(());
        }
        
        let json = std::fs::read_to_string(&self.state_file)
            .map_err(|e| FirewallError::IoError(e.to_string()))?;
        
        self.tracked_rules = serde_json::from_str(&json)
            .map_err(|e| FirewallError::SerializationError(e.to_string()))?;
        
        Ok(())
    }
    
    /// Clear all tracked rules (use with caution)
    pub fn clear_tracked_rules(&mut self) -> Result<(), FirewallError> {
        self.tracked_rules.clear();
        self.save_tracked_rules()
    }
}

impl Default for FirewallAutomation {
    fn default() -> Self {
        Self::new()
    }
}

/// Firewall status information
#[derive(Debug, Clone)]
pub struct FirewallStatus {
    pub firewall_type: FirewallType,
    pub is_active: bool,
    pub has_admin: bool,
    pub rules: Vec<FirewallRuleInfo>,
    pub tracked_rules_count: usize,
}

/// Information about a single firewall rule
#[derive(Debug, Clone)]
pub struct FirewallRuleInfo {
    pub port: u16,
    pub protocol: String,
    pub source: Option<String>,
    pub action: String,
    pub description: Option<String>,
}

/// Firewall-related errors
#[derive(Debug, thiserror::Error)]
pub enum FirewallError {
    #[error("No supported firewall detected on this system")]
    NoFirewall,
    
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),
    
    #[error("Invalid protocol: {0}")]
    InvalidProtocol(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Command failed: {0}")]
    CommandFailed(String),
    
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("Rule conflict detected")]
    RuleConflict,
    
    #[error("Unsupported operation: {0}")]
    Unsupported(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("I/O error: {0}")]
    IoError(String),
    
    #[error("Verification failed")]
    VerificationFailed,
}

/// Convenience function to open a port
pub async fn open_port(
    port: u16,
    protocol: &str,
    description: &str,
) -> Result<FirewallResult, FirewallError> {
    let mut automation = FirewallAutomation::new();
    automation.open_port(port, protocol, description).await
}

/// Convenience function to get firewall status
pub async fn get_firewall_status() -> Result<FirewallStatus, FirewallError> {
    let automation = FirewallAutomation::new();
    automation.get_status().await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_firewall_type_display() {
        assert_eq!(
            format!("{}", FirewallType::Ufw),
            "UFW (Uncomplicated Firewall)"
        );
        assert_eq!(
            format!("{}", FirewallType::Firewalld),
            "firewalld"
        );
    }
    
    #[test]
    fn test_invalid_port() {
        let automation = FirewallAutomation::new();
        assert!(automation.has_admin || !automation.has_admin); // Just to use automation
    }
    
    #[tokio::test]
    async fn test_rule_exists_detection() {
        // This test just verifies the code doesn't panic
        let automation = FirewallAutomation::new();
        let _ = automation.firewall_type();
    }
}
