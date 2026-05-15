//! GPTL Routing Module
//!
//! Provides secure routing with defenses against:
//! - BGP hijacking attacks (RAPTOR)
//! - Guard discovery attacks (Overlier-Syverson)
//! - Sybil attacks
//! - Sniper attacks (resource exhaustion)
//! - Timing attacks
//! - DNS leakage
//! - WebRTC leakage
//! - Circuit management with health monitoring and rotation

pub mod bgp_protection;
pub mod guard_management;
pub mod resource_protection;
pub mod dns_protection;
pub mod webrtc_protection;
pub mod sybil_defense;
pub mod failover;
pub mod circuit;
pub mod rpki_rtr;
pub mod transport_bridge;

// Re-export failover types
pub use failover::{
    FailoverManager, FailoverConfig, FailoverEvent, FailoverResult, FailoverError,
    FailoverStatistics, CircuitInfo, CircuitStatus, FailureType,
};

// Re-export circuit management types
pub use circuit::{
    CircuitManager, CircuitManagerConfig, CircuitManagerEvent, CircuitManagerStatistics,
    CircuitHandle, CircuitHealthMonitor, CircuitPool, CircuitPoolConfig,
    CircuitBuilder, CircuitId, HealthMonitorConfig, HealthStatistics, HealthStatus,
    PoolCircuit, PoolCircuitState, PoolEvent, PoolError, PoolStatistics,
    RetireReason, RotationEvent, RotationPolicy, RotationStatistics, RotationTrigger,
    CircuitManagerBuilder, create_circuit_manager, create_circuit_manager_with_pool,
};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Extended routing configuration with circuit management
#[derive(Debug, Clone)]
pub struct ExtendedRoutingConfig {
    /// Base routing configuration
    pub routing: RoutingConfig,
    /// Circuit pool configuration
    pub circuit_pool: CircuitPoolConfig,
    /// Health monitor configuration
    pub health_monitor: HealthMonitorConfig,
    /// Rotation policy
    pub rotation_policy: RotationPolicy,
    /// Enable circuit management
    pub enable_circuit_management: bool,
}

impl Default for ExtendedRoutingConfig {
    fn default() -> Self {
        Self {
            routing: RoutingConfig::default(),
            circuit_pool: CircuitPoolConfig::default(),
            health_monitor: HealthMonitorConfig::default(),
            rotation_policy: RotationPolicy::default(),
            enable_circuit_management: true,
        }
    }
}

/// Routing configuration
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Enable BGP protection
    pub bgp_protection: bool,
    /// Enable guard management
    pub guard_management: bool,
    /// Enable resource protection
    pub resource_protection: bool,
    /// Enable DNS protection
    pub dns_protection: bool,
    /// Enable WebRTC protection
    pub webrtc_protection: bool,
    /// Enable Sybil defense
    pub sybil_defense: bool,
    /// Security level
    pub security_level: SecurityLevel,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            bgp_protection: true,
            guard_management: true,
            resource_protection: true,
            dns_protection: true,
            webrtc_protection: true,
            sybil_defense: true,
            security_level: SecurityLevel::Enhanced,
        }
    }
}

/// Security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Standard,
    Enhanced,
    Maximum,
}

/// Main routing manager
pub struct RoutingManager {
    config: Arc<RwLock<RoutingConfig>>,
    bgp_guard: Option<bgp_protection::BgpGuard>,
    guard_manager: Option<guard_management::GuardManager>,
    resource_guard: Option<resource_protection::ResourceGuard>,
    dns_guard: Option<dns_protection::DnsGuard>,
    webrtc_guard: Option<webrtc_protection::WebrtcGuard>,
    sybil_shield: Option<sybil_defense::SybilShield>,
}

impl RoutingManager {
    /// Create new routing manager
    pub fn new(config: RoutingConfig) -> Self {
        let config = Arc::new(RwLock::new(config));
        
        Self {
            bgp_guard: Some(bgp_protection::BgpGuard::new(config.clone())),
            guard_manager: Some(guard_management::GuardManager::new(config.clone())),
            resource_guard: Some(resource_protection::ResourceGuard::new(config.clone())),
            dns_guard: Some(dns_protection::DnsGuard::new(config.clone())),
            webrtc_guard: Some(webrtc_protection::WebrtcGuard::new(config.clone())),
            sybil_shield: Some(sybil_defense::SybilShield::new(config.clone())),
            config,
        }
    }

    /// Initialize all routing protections
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        let config = self.config.read().await;
        
        if config.bgp_protection {
            if let Some(ref guard) = self.bgp_guard {
                guard.initialize().await?;
            }
        }
        
        if config.guard_management {
            if let Some(ref manager) = self.guard_manager {
                manager.initialize().await?;
            }
        }
        
        if config.resource_protection {
            if let Some(ref guard) = self.resource_guard {
                guard.initialize().await?;
            }
        }
        
        if config.dns_protection {
            if let Some(ref guard) = self.dns_guard {
                guard.initialize().await?;
            }
        }
        
        if config.webrtc_protection {
            if let Some(ref guard) = self.webrtc_guard {
                guard.initialize().await?;
            }
        }
        
        if config.sybil_defense {
            if let Some(ref shield) = self.sybil_shield {
                shield.initialize().await?;
            }
        }
        
        Ok(())
    }

    /// Select secure path
    pub async fn select_path(&self, destination: &IpAddr) -> Result<Path, RoutingError> {
        // Check BGP protection
        if let Some(ref guard) = self.bgp_guard {
            if let Some(threat) = guard.check_route(destination).await? {
                return Err(RoutingError::BgpThreatDetected(threat));
            }
        }
        
        // Get guards from guard manager
        let guards = if let Some(ref manager) = self.guard_manager {
            manager.select_guards().await?
        } else {
            Vec::new()
        };
        
        // Verify guards against Sybil defense
        if let Some(ref shield) = self.sybil_shield {
            for guard in &guards {
                if !shield.verify_relay(&guard.identity).await? {
                    return Err(RoutingError::SybilDetected(guard.identity.clone()));
                }
            }
        }
        
        // Build path
        Ok(Path {
            guards,
            destination: *destination,
        })
    }

    /// Protect DNS query
    pub async fn protect_dns(&self, query: &str) -> Result<Vec<u8>, RoutingError> {
        if let Some(ref guard) = self.dns_guard {
            guard.resolve_secure(query).await
        } else {
            Err(RoutingError::DnsProtectionDisabled)
        }
    }

    /// Protect WebRTC
    pub async fn protect_webrtc(&self) -> Result<WebrtcConfig, RoutingError> {
        if let Some(ref guard) = self.webrtc_guard {
            guard.get_secure_config().await
        } else {
            Err(RoutingError::WebrtcProtectionDisabled)
        }
    }

    /// Allocate circuit resources
    pub async fn allocate_circuit(&self, pow: ProofOfWork) -> Result<CircuitAllocation, RoutingError> {
        if let Some(ref guard) = self.resource_guard {
            guard.allocate(pow).await
        } else {
            Err(RoutingError::ResourceProtectionDisabled)
        }
    }
}

/// Path through the network
#[derive(Debug, Clone)]
pub struct Path {
    /// Guard nodes
    pub guards: Vec<GuardInfo>,
    /// Destination
    pub destination: IpAddr,
}

/// Guard information
#[derive(Debug, Clone)]
pub struct GuardInfo {
    pub identity: String,
    pub address: String,
    pub bandwidth: u64,
    pub layer: GuardLayer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardLayer {
    First,
    Second,
    Third,
}

/// Proof of work for resource allocation
#[derive(Debug, Clone)]
pub struct ProofOfWork {
    /// Target difficulty (number of required leading zero bits in `hash`).
    pub difficulty: u32,
    /// Caller-chosen circuit identifier mixed into the hash input.
    /// The verifier recomputes `SHA256(circuit_id || nonce)` and rejects any
    /// PoW whose submitted `hash` does not match — without this binding,
    /// an attacker can submit `hash: vec![0; 32]` and pass verification.
    pub circuit_id: u32,
    /// Brute-force counter found by the prover.
    pub nonce: u64,
    /// `SHA256(circuit_id.to_le_bytes() || nonce.to_le_bytes())`.
    pub hash: Vec<u8>,
}

/// Circuit allocation
#[derive(Debug, Clone)]
pub struct CircuitAllocation {
    pub circuit_id: u32,
    pub memory_quota: usize,
    pub bandwidth_quota: u64,
}

/// WebRTC secure configuration
#[derive(Debug, Clone)]
pub struct WebrtcConfig {
    pub stun_servers: Vec<String>,
    pub turn_servers: Vec<String>,
    pub block_local_ips: bool,
    pub force_relay: bool,
}

/// Routing errors
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error("BGP threat detected: {0}")]
    BgpThreatDetected(String),
    #[error("Sybil attack detected: {0}")]
    SybilDetected(String),
    #[error("DNS protection disabled")]
    DnsProtectionDisabled,
    #[error("WebRTC protection disabled")]
    WebrtcProtectionDisabled,
    #[error("Resource protection disabled")]
    ResourceProtectionDisabled,
    #[error("BGPv3 validation failed")]
    BgpValidationFailed,
    #[error("Guard selection failed: {0}")]
    GuardSelectionFailed(String),
    #[error("Resource allocation failed: {0}")]
    ResourceAllocationFailed(String),
    #[error("Circuit management error: {0}")]
    CircuitManagementError(String),
}

/// Default circuit builder implementation using the routing layer
pub struct RoutingCircuitBuilder {
    /// Relay selector for building circuits
    selector: Option<Arc<dyn gptl_core::relay_registry::RelayRegistry + Send + Sync>>,
}

impl RoutingCircuitBuilder {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self { selector: None }
    }

    /// Set the relay selector
    pub fn with_selector<R: gptl_core::relay_registry::RelayRegistry + Send + Sync + 'static>(
        mut self,
        selector: Arc<R>,
    ) -> Self {
        self.selector = Some(selector);
        self
    }
}

impl Default for RoutingCircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl circuit::CircuitBuilder for RoutingCircuitBuilder {
    async fn build_circuit(
        &self,
        circuit_id: circuit::CircuitId,
    ) -> Result<Vec<String>, circuit::PoolError> {
        // In production, this would use the relay selector to build a real circuit
        // For now, simulate circuit building with a delay
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        // Generate a mock circuit path
        Ok(vec![
            format!("guard_{}_entry", circuit_id),
            format!("middle_{}_relay", circuit_id),
            format!("exit_{}_relay", circuit_id),
        ])
    }

    async fn test_circuit(&self, _path: &[String]) -> Result<bool, circuit::PoolError> {
        // Simulate circuit test
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(true)
    }

    async fn close_circuit(
        &self,
        _circuit_id: circuit::CircuitId,
    ) -> Result<(), circuit::PoolError> {
        // Simulate circuit close
        Ok(())
    }
}
