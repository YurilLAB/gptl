//! IP-based access control
//!
//! Supports both exact-IP and CIDR-range entries, in both blocklist
//! ("block these networks") and allowlist ("only permit these networks")
//! modes.  The previous implementation only handled exact IPs via a
//! `HashMap<IpAddr, ..>`, so you couldn't block `192.168.0.0/16` or
//! restrict access to `10.0.0.0/8` without enumerating every address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use tokio::sync::RwLock;

pub mod geolocation;
pub mod threat_intel;

pub use geolocation::GeoBlocker;
pub use threat_intel::ThreatIntelligence;

/// IP allowlist/blocklist
#[derive(Debug)]
pub struct IpAllowlist {
    /// Exact-IP blocklist (kept for backward compatibility with
    /// callers that pass a single `IpAddr`).
    blocked_ips: Arc<RwLock<HashMap<IpAddr, BlockedIpInfo>>>,
    /// CIDR-range blocklist.  Each entry covers any IP inside the prefix.
    blocked_cidrs: Arc<RwLock<Vec<BlockedCidrEntry>>>,
    /// Optional allowlist.  When non-empty, ONLY traffic whose source IP
    /// is contained in one of these prefixes is permitted.  Empty
    /// allowlist means "permit everything not explicitly blocked."
    allowed_cidrs: Arc<RwLock<Vec<IpNet>>>,
    geo_blocker: Option<GeoBlocker>,
    threat_intel: Option<ThreatIntelligence>,
}

impl IpAllowlist {
    /// Create new allowlist
    pub fn new() -> Self {
        Self {
            blocked_ips: Arc::new(RwLock::new(HashMap::new())),
            blocked_cidrs: Arc::new(RwLock::new(Vec::new())),
            allowed_cidrs: Arc::new(RwLock::new(Vec::new())),
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

    /// Check if IP is allowed.  Order of checks:
    ///   1. CIDR allowlist (if non-empty, source MUST be inside one entry)
    ///   2. Exact-IP blocklist
    ///   3. CIDR blocklist
    ///   4. Geoblocking
    ///   5. Threat intelligence
    pub async fn is_allowed(&self, ip: IpAddr) -> crate::Result<()> {
        // 1. Allowlist (if any) — fail-closed.
        {
            let allow = self.allowed_cidrs.read().await;
            if !allow.is_empty() && !allow.iter().any(|net| net.contains(&ip)) {
                return Err(crate::RelayError::IpBlocked(format!(
                    "{} is not in any configured allowlist CIDR",
                    ip
                )));
            }
        }

        // 2. Exact-IP blocklist
        {
            let blocked = self.blocked_ips.read().await;
            if let Some(info) = blocked.get(&ip) {
                if info.expires_at.map(|e| e > Utc::now()).unwrap_or(true) {
                    return Err(crate::RelayError::IpBlocked(info.reason.clone()));
                }
            }
        }

        // 3. CIDR blocklist
        {
            let cidrs = self.blocked_cidrs.read().await;
            for entry in cidrs.iter() {
                if entry.expires_at.map(|e| e <= Utc::now()).unwrap_or(false) {
                    continue; // expired
                }
                if entry.cidr.contains(&ip) {
                    return Err(crate::RelayError::IpBlocked(format!(
                        "{} blocked by CIDR rule {} ({})",
                        ip, entry.cidr, entry.reason
                    )));
                }
            }
        }

        // 4. Geoblocking
        if let Some(ref geo) = self.geo_blocker {
            geo.check_ip(ip).await?;
        }

        // 5. Threat intelligence
        if let Some(ref intel) = self.threat_intel {
            if intel.check_ip(ip).await.is_some() {
                return Err(crate::RelayError::IpBlocked("Threat detected".to_string()));
            }
        }

        Ok(())
    }

    /// Block an exact IP.  Mainly kept for backward compatibility;
    /// prefer `block_cidr` for new code (a `/32` or `/128` accepts
    /// single hosts and uses the same code path as range blocks).
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

    /// Block a CIDR range.  Accepts both IPv4 (e.g. `"192.168.0.0/16"`)
    /// and IPv6 (e.g. `"2001:db8::/32"`).  `duration: None` means permanent.
    pub async fn block_cidr(
        &self,
        cidr: &str,
        reason: impl Into<String>,
        duration: Option<Duration>,
    ) -> crate::Result<()> {
        let parsed: IpNet = cidr.parse().map_err(|e: ipnet::AddrParseError| {
            crate::RelayError::ConfigError(format!("invalid CIDR '{}': {}", cidr, e))
        })?;
        let mut cidrs = self.blocked_cidrs.write().await;
        cidrs.push(BlockedCidrEntry {
            cidr: parsed,
            reason: reason.into(),
            blocked_at: Utc::now(),
            expires_at: duration.map(|d| Utc::now() + d),
        });
        Ok(())
    }

    /// Add a CIDR to the allowlist.  As soon as the allowlist is
    /// non-empty, only traffic from one of these CIDRs is permitted.
    pub async fn allow_cidr(&self, cidr: &str) -> crate::Result<()> {
        let parsed: IpNet = cidr.parse().map_err(|e: ipnet::AddrParseError| {
            crate::RelayError::ConfigError(format!("invalid CIDR '{}': {}", cidr, e))
        })?;
        let mut allow = self.allowed_cidrs.write().await;
        allow.push(parsed);
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

/// Blocked CIDR range entry.
#[derive(Debug, Clone)]
pub struct BlockedCidrEntry {
    /// The blocked network prefix.
    pub cidr: IpNet,
    /// Operator-supplied reason; surfaced in the error message.
    pub reason: String,
    /// When the entry was added.
    pub blocked_at: DateTime<Utc>,
    /// `None` for permanent, `Some(t)` for time-limited.
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_exact_ip_still_works() {
        let acl = IpAllowlist::new();
        let ip: IpAddr = "10.20.30.40".parse().unwrap();
        acl.block_ip(ip, "test", None).await.unwrap();
        assert!(acl.is_allowed(ip).await.is_err());
        assert!(acl.is_allowed("10.20.30.41".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn test_block_cidr_ipv4_matches_range() {
        let acl = IpAllowlist::new();
        acl.block_cidr("192.168.0.0/16", "private network", None).await.unwrap();

        assert!(acl.is_allowed("192.168.1.1".parse().unwrap()).await.is_err());
        assert!(acl.is_allowed("192.168.255.255".parse().unwrap()).await.is_err());
        assert!(acl.is_allowed("192.169.0.1".parse().unwrap()).await.is_ok(),
            "neighbor /16 must NOT be in the blocked range");
    }

    #[tokio::test]
    async fn test_block_cidr_ipv6_matches_range() {
        let acl = IpAllowlist::new();
        acl.block_cidr("2001:db8::/32", "doc-prefix", None).await.unwrap();

        assert!(acl.is_allowed("2001:db8::1".parse().unwrap()).await.is_err());
        assert!(acl.is_allowed("2001:db8:beef::1".parse().unwrap()).await.is_err());
        assert!(acl.is_allowed("2001:db9::1".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn test_allowlist_non_empty_blocks_everything_else() {
        let acl = IpAllowlist::new();
        acl.allow_cidr("10.0.0.0/8").await.unwrap();

        assert!(acl.is_allowed("10.1.2.3".parse().unwrap()).await.is_ok());
        // Anything OUTSIDE the allowlist is blocked, even though the blocklist is empty.
        assert!(acl.is_allowed("192.168.0.1".parse().unwrap()).await.is_err(),
            "an IP not in any allowlist CIDR must be blocked");
    }

    #[tokio::test]
    async fn test_allowlist_empty_means_no_restriction() {
        // Sanity: if you never add an allow_cidr, the allowlist is empty
        // and behaviour matches the old blocklist-only mode.
        let acl = IpAllowlist::new();
        assert!(acl.is_allowed("8.8.8.8".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn test_block_cidr_invalid_input_returns_config_error() {
        let acl = IpAllowlist::new();
        let result = acl.block_cidr("not a cidr", "x", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_single_host_cidr_acts_like_exact_block() {
        let acl = IpAllowlist::new();
        acl.block_cidr("203.0.113.5/32", "honeypot", None).await.unwrap();

        assert!(acl.is_allowed("203.0.113.5".parse().unwrap()).await.is_err());
        assert!(acl.is_allowed("203.0.113.6".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn test_expired_cidr_block_is_ignored() {
        let acl = IpAllowlist::new();
        acl.block_cidr("10.0.0.0/8", "temp", Some(Duration::milliseconds(-1)))
            .await
            .unwrap();
        // Already expired — should NOT block.
        assert!(acl.is_allowed("10.0.0.1".parse().unwrap()).await.is_ok());
    }
}
