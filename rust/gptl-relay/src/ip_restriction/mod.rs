//! IP-based access control
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

pub mod geolocation;
pub mod threat_intel;

pub use geolocation::GeoBlocker;
pub use threat_intel::ThreatIntelligence;

/// IP allowlist/blocklist
#[derive(Debug)]
pub struct IpAllowlist {
    blocked_ips: Arc<RwLock<HashMap<IpAddr, BlockedIpInfo>>>,
    geo_blocker: Option<GeoBlocker>,
    threat_intel: Option<ThreatIntelligence>,
}

impl IpAllowlist {
    /// Create new allowlist
    pub fn new() -> Self {
        Self {
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            geo_blocker: None,
            threat_intel: None,
        }
    }

    /// Add geoblocking
    pub fn with_geoblocking(mut self, geo_blocker: GeoBlocker) -> Self {
        self.geo_blocker = Some(geo_blocker);
        self
    }

    /// Add threat intelligence
    pub fn with_threat_intel(mut self, threat_intel: ThreatIntelligence) -> Self {
        self.threat_intel = Some(threat_intel);
        self
    }

    /// Check if IP is allowed
    pub async fn is_allowed(&self, ip: IpAddr) -> crate::Result<()> {
        // Check blocked IPs
        let blocked = self.blocked_ips.read().await;
        if let Some(info) = blocked.get(&ip) {
            if info.expires_at.map(|e| e > Utc::now()).unwrap_or(true) {
                return Err(crate::RelayError::IpBlocked(info.reason.clone()));
            }
        }

        // Check geoblocking
        if let Some(ref geo) = self.geo_blocker {
            geo.check_ip(ip).await?;
        }

        // Check threat intelligence
        if let Some(ref intel) = self.threat_intel {
            if let Some(_threat) = intel.check_ip(ip).await {
                return Err(crate::RelayError::IpBlocked("Threat detected".to_string()));
            }
        }

        Ok(())
    }

    /// Block an IP
    pub async fn block_ip(&self, ip: IpAddr, reason: impl Into<String>, duration: Option<Duration>) -> crate::Result<()> {
        let mut blocked = self.blocked_ips.write().await;
        blocked.insert(ip, BlockedIpInfo {
            ip,
            reason: reason.into(),
            blocked_at: Utc::now(),
            expires_at: duration.map(|d| Utc::now() + d),
        });
        Ok(())
    }
}

impl Default for IpAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocked IP info
#[derive(Debug, Clone)]
pub struct BlockedIpInfo {
    pub ip: IpAddr,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
