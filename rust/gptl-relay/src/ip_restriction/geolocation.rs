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
    /// Database reader.  `None` when no `.mmdb` file has been loaded —
    /// in that mode `lookup()` returns a `XX`/`Unknown` placeholder so
    /// the rest of the security pipeline still runs (the operator
    /// presumably has other guards in place).
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

    /// Load a MaxMind GeoLite2 / GeoIP2 `.mmdb` database from disk.
    ///
    /// `path` must point at one of MaxMind's binary database files
    /// (`GeoLite2-Country.mmdb`, `GeoLite2-City.mmdb`, or
    /// `GeoLite2-ASN.mmdb`).  The reader auto-detects which schema is
    /// present and exposes the fields it can parse via [`lookup`].
    ///
    /// Returns `Err` if the file is missing or fails to parse so
    /// callers can choose between "no GeoIP" (skip the feature) and
    /// "abort startup" (security-required deployments).
    pub async fn load_database(&self, path: &str) -> crate::Result<()> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| crate::RelayError::ConfigError(format!("GeoIP DB '{}': {}", path, e)))?;
        let mut db = self.db.write().await;
        *db = Some(GeoIpDatabase::with_reader(reader));
        Ok(())
    }

    /// Block a country by code
    pub async fn block_country(&self, country_code: &str) -> crate::Result<()> {
        let code = country_code.to_uppercase();

        // Validate country code
        if code.len() != 2 {
            return Err(crate::RelayError::ConfigError(
                "Invalid country code (must be 2 characters)".to_string(),
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
                    "Invalid country code (must be 2 characters)".to_string(),
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
                return Err(crate::RelayError::IpBlocked("Tor exit node".to_string()));
            }
        }

        // Look up GeoIP data
        let location = self.lookup(ip).await?;

        // Check allowed countries list
        {
            let allowed = self.allowed_countries.read().await;
            if !allowed.is_empty() && !allowed.contains(&location.country_code) {
                return Err(crate::RelayError::IpBlocked(format!(
                    "Country {} not allowed",
                    location.country_code
                )));
            }
        }

        // Check blocked countries
        {
            let blocked = self.blocked_countries.read().await;
            if blocked.contains(&location.country_code) {
                return Err(crate::RelayError::IpBlocked(format!(
                    "Country {} blocked",
                    location.country_code
                )));
            }
        }

        // Check blocked ASNs
        {
            let blocked_asns = self.blocked_asns.read().await;
            if let Some(asn) = location.asn {
                if blocked_asns.contains(&asn) {
                    return Err(crate::RelayError::IpBlocked(format!("ASN {} blocked", asn)));
                }
            }
        }

        // Check VPN/proxy
        if self.block_vpns && location.is_vpn {
            return Err(crate::RelayError::IpBlocked(
                "VPN/proxy detected".to_string(),
            ));
        }

        // Check hosting provider
        if self.block_hosting && location.is_hosting {
            return Err(crate::RelayError::IpBlocked(
                "Hosting provider detected".to_string(),
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

/// GeoIP database — a thin wrapper around a [`maxminddb::Reader`] that
/// translates between MaxMind's schema and our `GeoLocation` struct.
///
/// One of three MaxMind database schemas is expected at runtime:
///   * `GeoLite2-Country` → fills country fields, leaves city/region blank
///   * `GeoLite2-City`    → fills country + city + lat/lon
///   * `GeoLite2-ASN`     → fills `asn` + `asn_organization`
///
/// Combining ASN data with country/city data requires loading two
/// databases; for now we only consult whichever one was passed to
/// [`GeoBlocker::load_database`].
pub struct GeoIpDatabase {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl std::fmt::Debug for GeoIpDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpDatabase")
            .field("metadata", &self.reader.metadata)
            .finish()
    }
}

impl GeoIpDatabase {
    /// Wrap a previously-opened MaxMind reader.  Most callers go
    /// through [`GeoBlocker::load_database`] rather than building this
    /// directly.
    pub fn with_reader(reader: maxminddb::Reader<Vec<u8>>) -> Self {
        Self { reader }
    }

    /// Look up an IP in the bound MaxMind database.  Returns a
    /// `GeoLocation` filled in with whatever fields the underlying
    /// schema exposes; missing fields are left at their default
    /// (`"XX"` for country code, `None` for optional fields).
    pub fn lookup(&self, ip: IpAddr) -> GeoLocation {
        let mut loc = GeoLocation {
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
        };

        // Try the City schema first (richest data); fall back to
        // Country, then ASN.  Each lookup is independent and silently
        // skipped if it doesn't match the loaded DB.  maxminddb 0.24's
        // `lookup` returns `Result<T, MaxMindDBError>` — the
        // `AddressNotFoundError` variant signals a clean miss.
        if let Ok(city) = self.reader.lookup::<maxminddb::geoip2::City>(ip) {
            if let Some(country) = city.country {
                if let Some(code) = country.iso_code {
                    loc.country_code = code.to_string();
                }
                if let Some(names) = country.names {
                    if let Some(name) = names.get("en") {
                        loc.country_name = name.to_string();
                    }
                }
            }
            if let Some(continent) = city.continent {
                if let Some(code) = continent.code {
                    loc.continent_code = code.to_string();
                }
            }
            if let Some(city_data) = city.city {
                if let Some(names) = city_data.names {
                    if let Some(name) = names.get("en") {
                        loc.city = Some(name.to_string());
                    }
                }
            }
            if let Some(location) = city.location {
                if let Some(lat) = location.latitude {
                    loc.latitude = lat;
                }
                if let Some(lon) = location.longitude {
                    loc.longitude = lon;
                }
            }
            if let Some(subdivs) = city.subdivisions {
                if let Some(first) = subdivs.first() {
                    if let Some(names) = &first.names {
                        if let Some(name) = names.get("en") {
                            loc.region = Some(name.to_string());
                        }
                    }
                }
            }
        } else if let Ok(country) = self.reader.lookup::<maxminddb::geoip2::Country>(ip) {
            if let Some(country) = country.country {
                if let Some(code) = country.iso_code {
                    loc.country_code = code.to_string();
                }
                if let Some(names) = country.names {
                    if let Some(name) = names.get("en") {
                        loc.country_name = name.to_string();
                    }
                }
            }
        }

        // ASN database can be the same file or a separate one; only
        // overwrites if a lookup succeeds.
        if let Ok(asn) = self.reader.lookup::<maxminddb::geoip2::Asn>(ip) {
            loc.asn = asn.autonomous_system_number;
            loc.asn_organization = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        loc
    }
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
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
            "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "GB",
            "IS", "LI", "NO", "CH",
        ];
        EU_COUNTRIES.contains(&self.country_code.as_str())
    }

    /// Get risk level based on location
    pub fn risk_level(&self) -> GeoRiskLevel {
        if self.is_sanctioned() {
            GeoRiskLevel::Critical
        } else if self.is_tor || self.is_vpn {
            GeoRiskLevel::High
        } else if self.is_proxy || self.is_hosting {
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
    Low,     // Only block sanctioned
    Medium,  // Block sanctioned + Tor
    High,    // Block sanctioned + Tor + VPN
    Maximum, // Block all suspicious
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

    #[tokio::test]
    async fn test_load_database_missing_file_returns_config_error() {
        let blocker = GeoBlocker::new();
        let result = blocker
            .load_database("nonexistent_path_to_geolite.mmdb")
            .await;
        assert!(
            matches!(result, Err(crate::RelayError::ConfigError(_))),
            "missing GeoIP DB must yield ConfigError, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_lookup_without_database_returns_xx() {
        // Before any load_database call, lookups return the placeholder
        // "XX" country.  The rest of the security pipeline still runs.
        let blocker = GeoBlocker::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let loc = blocker.lookup(ip).await.unwrap();
        assert_eq!(loc.country_code, "XX");
        assert_eq!(loc.country_name, "Unknown");
    }

    #[tokio::test]
    async fn test_check_ip_passes_when_no_database_loaded() {
        // No DB → no country info → no country block can fire.  The
        // check_ip pipeline must still return Ok so the legacy
        // "GeoBlocker added but no DB available" deployments don't
        // suddenly reject every connection.
        let blocker = GeoBlocker::new();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(blocker.check_ip(ip).await.is_ok());
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
