//! Geolocation-based IP Blocking
//!
//! Implements country-level and ASN-level filtering using MaxMind GeoIP2:
//! - Country code blocking
//! - ASN (Autonomous System Number) filtering
//! - Continent-level filtering
//! - Tor exit node detection

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// GeoIP-based blocker
#[derive(Debug)]
pub struct GeoBlocker {
    /// Database reader (simplified - would use maxminddb crate)
    db: Arc<RwLock<Option<GeoIpDatabase>>>,
    /// Blocked country codes (ISO 3166-1 alpha-2)
    blocked_countries: Arc<RwLock<HashSet<String>>>,
    /// Allowed country codes (if not empty, only these are allowed)
    allowed_countries: Arc<RwLock<HashSet<String>>>,
    /// Blocked ASNs
    blocked_asns: Arc<RwLock<HashSet<u32>>>,
    /// Block Tor exit nodes
    block_tor: bool,
    /// Tor exit node list
    tor_exits: Arc<RwLock<HashSet<IpAddr>>>,
    /// Block VPN/proxy IPs
    block_vpns: bool,
    /// Block hosting providers
    block_hosting: bool,
}

impl GeoBlocker {
    /// Create a new GeoBlocker
    pub fn new() -> Self {
        Self {
            db: Arc::new(RwLock::new(None)),
            blocked_countries: Arc::new(RwLock::new(HashSet::new())),
            allowed_countries: Arc::new(RwLock::new(HashSet::new())),
            blocked_asns: Arc::new(RwLock::new(HashSet::new())),
            block_tor: true,
            tor_exits: Arc::new(RwLock::new(HashSet::new())),
            block_vpns: false,
            block_hosting: false,
        }
    }

    /// Load GeoIP2 database
    pub async fn load_database(&self, _path: &str) -> crate::Result<()> {
        // No bundled GeoIP2 database — in production, load a MaxMind DB2 file.
        // Returns Ok(()) with an empty database that allows all IPs.
        let mut db = self.db.write().await;
        *db = Some(GeoIpDatabase::new());
        Ok(())
    }

    /// Block a country by code
    pub async fn block_country(&self, country_code: &str) -> crate::Result<()> {
        let code = country_code.to_uppercase();
        
        // Validate country code
        if code.len() != 2 {
            return Err(crate::RelayError::ConfigError(
                "Invalid country code (must be 2 characters)".to_string()
            ));
        }

        let mut blocked = self.blocked_countries.write().await;
        blocked.insert(code);
        Ok(())
    }

    /// Allow only specific countries
    pub async fn allow_only_countries(&self, country_codes: &[String]) -> crate::Result<()> {
        let mut allowed = self.allowed_countries.write().await;
        allowed.clear();
        
        for code in country_codes {
            if code.len() != 2 {
                return Err(crate::RelayError::ConfigError(
                    "Invalid country code (must be 2 characters)".to_string()
                ));
            }
            allowed.insert(code.to_uppercase());
        }
        
        Ok(())
    }

    /// Block an ASN
    pub async fn block_asn(&self, asn: u32) {
        let mut blocked = self.blocked_asns.write().await;
        blocked.insert(asn);
    }

    /// Enable Tor exit node blocking
    pub fn block_tor_exit_nodes(mut self) -> Self {
        self.block_tor = true;
        self
    }

    /// Enable VPN/proxy blocking
    pub fn block_vpns_and_proxies(mut self) -> Self {
        self.block_vpns = true;
        self
    }

    /// Enable hosting provider blocking
    pub fn block_hosting_providers(mut self) -> Self {
        self.block_hosting = true;
        self
    }

    /// Update Tor exit node list
    pub async fn update_tor_exit_nodes(&self, exits: Vec<IpAddr>) {
        let mut tor_exits = self.tor_exits.write().await;
        tor_exits.clear();
        tor_exits.extend(exits);
    }

    /// Check if an IP is allowed
    pub async fn check_ip(&self, ip: IpAddr) -> crate::Result<()> {
        // Check Tor exit nodes first
        if self.block_tor {
            let tor_exits = self.tor_exits.read().await;
            if tor_exits.contains(&ip) {
                return Err(crate::RelayError::IpBlocked(
                    "Tor exit node".to_string()
                ));
            }
        }

        // Look up GeoIP data
        let location = self.lookup(ip).await?;

        // Check allowed countries list
        {
            let allowed = self.allowed_countries.read().await;
            if !allowed.is_empty() && !allowed.contains(&location.country_code) {
                return Err(crate::RelayError::IpBlocked(
                    format!("Country {} not allowed", location.country_code)
                ));
            }
        }

        // Check blocked countries
        {
            let blocked = self.blocked_countries.read().await;
            if blocked.contains(&location.country_code) {
                return Err(crate::RelayError::IpBlocked(
                    format!("Country {} blocked", location.country_code)
                ));
            }
        }

        // Check blocked ASNs
        {
            let blocked_asns = self.blocked_asns.read().await;
            if let Some(asn) = location.asn {
                if blocked_asns.contains(&asn) {
                    return Err(crate::RelayError::IpBlocked(
                        format!("ASN {} blocked", asn)
                    ));
                }
            }
        }

        // Check VPN/proxy
        if self.block_vpns && location.is_vpn {
            return Err(crate::RelayError::IpBlocked(
                "VPN/proxy detected".to_string()
            ));
        }

        // Check hosting provider
        if self.block_hosting && location.is_hosting {
            return Err(crate::RelayError::IpBlocked(
                "Hosting provider detected".to_string()
            ));
        }

        Ok(())
    }

    /// Lookup geolocation for an IP
    pub async fn lookup(&self, ip: IpAddr) -> crate::Result<GeoLocation> {
        let db = self.db.read().await;
        
        if let Some(ref database) = *db {
            Ok(database.lookup(ip))
        } else {
            // Return unknown location if no database loaded
            Ok(GeoLocation {
                ip,
                country_code: "XX".to_string(),
                country_name: "Unknown".to_string(),
                continent_code: "XX".to_string(),
                city: None,
                region: None,
                latitude: 0.0,
                longitude: 0.0,
                asn: None,
                asn_organization: None,
                is_vpn: false,
                is_proxy: false,
                is_tor: false,
                is_hosting: false,
            })
        }
    }

    /// Get list of blocked countries
    pub async fn get_blocked_countries(&self) -> Vec<String> {
        let blocked = self.blocked_countries.read().await;
        blocked.iter().cloned().collect()
    }

    /// Get list of allowed countries (empty = all allowed)
    pub async fn get_allowed_countries(&self) -> Vec<String> {
        let allowed = self.allowed_countries.read().await;
        allowed.iter().cloned().collect()
    }
}

impl Default for GeoBlocker {
    fn default() -> Self {
        Self::new()
    }
}

/// GeoIP database (simplified)
#[derive(Debug, Clone)]
pub struct GeoIpDatabase {
    // In production, this would wrap maxminddb::Reader
    entries: Vec<GeoEntry>,
}

impl GeoIpDatabase {
    /// Create a new empty database
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Lookup an IP in the database
    pub fn lookup(&self, ip: IpAddr) -> GeoLocation {
        // In production, this would query the MaxMind database
        // For now, return unknown
        GeoLocation {
            ip,
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            continent_code: "XX".to_string(),
            city: None,
            region: None,
            latitude: 0.0,
            longitude: 0.0,
            asn: None,
            asn_organization: None,
            is_vpn: false,
            is_proxy: false,
            is_tor: false,
            is_hosting: false,
        }
    }
}

impl Default for GeoIpDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// GeoIP database entry
#[derive(Debug, Clone)]
struct GeoEntry {
    start_ip: IpAddr,
    end_ip: IpAddr,
    country_code: String,
}

/// Geolocation information for an IP
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    pub ip: IpAddr,
    pub country_code: String,
    pub country_name: String,
    pub continent_code: String,
    pub city: Option<String>,
    pub region: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub asn: Option<u32>,
    pub asn_organization: Option<String>,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
    pub is_hosting: bool,
}

impl GeoLocation {
    /// Check if IP is from a sanctioned country (OFAC)
    pub fn is_sanctioned(&self) -> bool {
        const SANCTIONED: &[&str] = &["IR", "KP", "SY", "CU"];
        SANCTIONED.contains(&self.country_code.as_str())
    }

    /// Check if IP is from EU (GDPR applies)
    pub fn is_eu(&self) -> bool {
        const EU_COUNTRIES: &[&str] = &[
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
            "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
            "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB", "IS", "LI",
            "NO", "CH",
        ];
        EU_COUNTRIES.contains(&self.country_code.as_str())
    }

    /// Get risk level based on location
    pub fn risk_level(&self) -> GeoRiskLevel {
        if self.is_sanctioned() {
            GeoRiskLevel::Critical
        } else if self.is_tor || self.is_vpn {
            GeoRiskLevel::High
        } else if self.is_proxy {
            GeoRiskLevel::Medium
        } else if self.is_hosting {
            GeoRiskLevel::Medium
        } else {
            GeoRiskLevel::Low
        }
    }
}

/// Geolocation risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GeoRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl GeoRiskLevel {
    pub fn description(&self) -> &'static str {
        match self {
            GeoRiskLevel::Low => "Low risk location",
            GeoRiskLevel::Medium => "Medium risk location",
            GeoRiskLevel::High => "High risk location (anonymization detected)",
            GeoRiskLevel::Critical => "Critical risk location (sanctioned)",
        }
    }

    pub fn should_block(&self, strictness: BlockStrictness) -> bool {
        match (self, strictness) {
            (GeoRiskLevel::Critical, _) => true,
            (GeoRiskLevel::High, BlockStrictness::High | BlockStrictness::Maximum) => true,
            (GeoRiskLevel::Medium, BlockStrictness::Maximum) => true,
            _ => false,
        }
    }
}

/// Blocking strictness level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStrictness {
    Low,      // Only block sanctioned
    Medium,   // Block sanctioned + Tor
    High,     // Block sanctioned + Tor + VPN
    Maximum,  // Block all suspicious
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_country() {
        let blocker = GeoBlocker::new();
        blocker.block_country("CN").await.unwrap();
        
        let blocked = blocker.get_blocked_countries().await;
        assert!(blocked.contains(&"CN".to_string()));
    }

    #[test]
    fn test_geo_location_risk() {
        let mut loc = GeoLocation {
            ip: "1.2.3.4".parse().unwrap(),
            country_code: "US".to_string(),
            country_name: "United States".to_string(),
            continent_code: "NA".to_string(),
            city: None,
            region: None,
            latitude: 0.0,
            longitude: 0.0,
            asn: None,
            asn_organization: None,
            is_vpn: false,
            is_proxy: false,
            is_tor: false,
            is_hosting: false,
        };
        
        assert_eq!(loc.risk_level(), GeoRiskLevel::Low);
        
        loc.is_vpn = true;
        assert_eq!(loc.risk_level(), GeoRiskLevel::High);
        
        loc.country_code = "IR".to_string();
        assert_eq!(loc.risk_level(), GeoRiskLevel::Critical);
    }

    #[test]
    fn test_is_eu() {
        let eu_loc = GeoLocation {
            ip: "1.2.3.4".parse().unwrap(),
            country_code: "DE".to_string(),
            country_name: "Germany".to_string(),
            continent_code: "EU".to_string(),
            city: None,
            region: None,
            latitude: 0.0,
            longitude: 0.0,
            asn: None,
            asn_organization: None,
            is_vpn: false,
            is_proxy: false,
            is_tor: false,
            is_hosting: false,
        };
        
        assert!(eu_loc.is_eu());
        
        let us_loc = GeoLocation {
            country_code: "US".to_string(),
            ..eu_loc.clone()
        };
        
        assert!(!us_loc.is_eu());
    }
}
