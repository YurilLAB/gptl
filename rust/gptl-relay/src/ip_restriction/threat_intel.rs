//! Threat Intelligence Integration
//!
//! Automatic IP blocking based on threat intelligence feeds:
//! - AbuseIPDB integration
//! - VirusTotal IP reputation
//! - AlienVault OTX
//! - Custom threat feeds
//! - C2 (Command & Control) detection

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

/// Threat intelligence manager
#[derive(Debug)]
pub struct ThreatIntelligence {
    /// Enabled threat feeds
    feeds: Vec<ThreatFeed>,
    /// Cached threat data
    cache: Arc<RwLock<HashMap<IpAddr, ThreatInfo>>>,
    /// Cache TTL
    cache_ttl: Duration,
    /// Minimum threat score to block
    min_threat_score: u8,
    /// Categories to always block
    auto_block_categories: Vec<ThreatCategory>,
    /// Statistics
    stats: Arc<RwLock<ThreatStats>>,
}

impl ThreatIntelligence {
    /// Create a new threat intelligence manager
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::hours(1),
            min_threat_score: 80,
            auto_block_categories: vec![
                ThreatCategory::Malware,
                ThreatCategory::C2,
                ThreatCategory::Botnet,
                ThreatCategory::Scanner,
            ],
            stats: Arc::new(RwLock::new(ThreatStats::default())),
        }
    }

    /// Configure cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Set minimum threat score to consider
    pub fn with_min_score(mut self, score: u8) -> Self {
        self.min_threat_score = score;
        self
    }

    /// Add a threat feed
    pub fn add_feed(&mut self, feed: ThreatFeed) {
        self.feeds.push(feed);
    }

    /// Check if an IP is a known threat
    pub async fn check_ip(&self, ip: IpAddr) -> Option<ThreatInfo> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(info) = cache.get(&ip) {
                if info.fetched_at + self.cache_ttl > Utc::now() {
                    return Some(info.clone());
                }
            }
        }

        // Query threat feeds
        let info = self.query_threat_feeds(ip).await;

        // Update cache
        if let Some(ref threat) = info {
            let mut cache = self.cache.write().await;
            cache.insert(ip, threat.clone());

            // Update stats
            let mut stats = self.stats.write().await;
            if threat.is_malicious() {
                stats.threats_detected += 1;
            }
        }

        info
    }

    /// Get threat score for an IP (0-100)
    pub async fn get_threat_score(&self, ip: IpAddr) -> u8 {
        if let Some(info) = self.check_ip(ip).await {
            info.score
        } else {
            0
        }
    }

    /// Query all configured threat feeds
    async fn query_threat_feeds(&self, ip: IpAddr) -> Option<ThreatInfo> {
        let mut aggregated = ThreatInfo {
            ip,
            score: 0,
            categories: Vec::new(),
            reports: Vec::new(),
            sources: Vec::new(),
            fetched_at: Utc::now(),
        };

        for feed in &self.feeds {
            if let Some(info) = feed.query(ip).await {
                // Merge threat information
                aggregated.score = aggregated.score.max(info.score);
                aggregated.categories.extend(info.categories);
                aggregated.reports.extend(info.reports);
                aggregated.sources.push(feed.name().to_string());
            }
        }

        // Remove duplicate categories
        aggregated.categories.sort();
        aggregated.categories.dedup();

        if aggregated.score >= self.min_threat_score {
            Some(aggregated)
        } else {
            None
        }
    }

    /// Report an IP to threat intelligence
    pub async fn report_ip(
        &self,
        ip: IpAddr,
        category: ThreatCategory,
        comment: &str,
    ) -> crate::Result<()> {
        // Report to all feeds that support reporting
        for feed in &self.feeds {
            if feed.supports_reporting() {
                feed.report(ip, category, comment).await?;
            }
        }

        // Update stats
        let mut stats = self.stats.write().await;
        stats.ips_reported += 1;

        Ok(())
    }

    /// Get threat statistics
    pub async fn get_stats(&self) -> ThreatStats {
        self.stats.read().await.clone()
    }

    /// Cleanup expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let cutoff = Utc::now() - self.cache_ttl;
        cache.retain(|_, info| info.fetched_at > cutoff);
    }

    /// Get cached threat info for an IP
    pub async fn get_cached(&self, ip: IpAddr) -> Option<ThreatInfo> {
        let cache = self.cache.read().await;
        cache.get(&ip).cloned()
    }
}

impl Default for ThreatIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

/// Threat feed interface
#[derive(Debug, Clone)]
pub enum ThreatFeed {
    /// AbuseIPDB feed
    AbuseIpDb {
        api_key: String,
    },
    /// VirusTotal feed
    VirusTotal {
        api_key: String,
    },
    /// AlienVault OTX
    AlienVaultOtx {
        api_key: String,
    },
    /// Custom CSV feed
    CustomCsv {
        url: String,
        refresh_interval: Duration,
    },
    /// Local blocklist
    LocalBlocklist {
        entries: Vec<(IpAddr, ThreatInfo)>,
    },
}

impl ThreatFeed {
    /// Get feed name
    pub fn name(&self) -> &str {
        match self {
            ThreatFeed::AbuseIpDb { .. } => "AbuseIPDB",
            ThreatFeed::VirusTotal { .. } => "VirusTotal",
            ThreatFeed::AlienVaultOtx { .. } => "AlienVault OTX",
            ThreatFeed::CustomCsv { .. } => "Custom CSV",
            ThreatFeed::LocalBlocklist { .. } => "Local Blocklist",
        }
    }

    /// Check if feed supports reporting
    pub fn supports_reporting(&self) -> bool {
        matches!(self, ThreatFeed::AbuseIpDb { .. })
    }

    /// Query the feed for an IP
    pub async fn query(&self, ip: IpAddr) -> Option<ThreatInfo> {
        match self {
            ThreatFeed::AbuseIpDb { api_key } => {
                self.query_abuseipdb(ip, api_key).await
            }
            ThreatFeed::VirusTotal { api_key } => {
                self.query_virustotal(ip, api_key).await
            }
            ThreatFeed::AlienVaultOtx { api_key } => {
                self.query_alienvault(ip, api_key).await
            }
            ThreatFeed::CustomCsv { .. } => {
                // Would fetch and parse CSV
                None
            }
            ThreatFeed::LocalBlocklist { entries } => {
                entries.iter()
                    .find(|(eip, _)| *eip == ip)
                    .map(|(_, info)| info.clone())
            }
        }
    }

    /// Report an IP to the feed
    pub async fn report(
        &self,
        ip: IpAddr,
        category: ThreatCategory,
        comment: &str,
    ) -> crate::Result<()> {
        match self {
            ThreatFeed::AbuseIpDb { api_key } => {
                self.report_abuseipdb(ip, category, comment, api_key).await
            }
            _ => Err(crate::RelayError::Internal(
                "Feed does not support reporting".to_string()
            )),
        }
    }

    async fn query_abuseipdb(&self, ip: IpAddr, api_key: &str) -> Option<ThreatInfo> {
        // AbuseIPDB API v2: https://docs.abuseipdb.com/
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build() {
            Ok(c) => c,
            Err(_) => return None,
        };

        let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90", ip);

        let response = client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let json: serde_json::Value = response.json().await.ok()?;
        let data = json.get("data")?;

        let abuse_score = data.get("abuseConfidenceScore")?.as_u64()? as u8;
        let is_whitelisted = data.get("isWhitelisted")?.as_bool().unwrap_or(false);

        if is_whitelisted {
            return None;
        }

        let mut categories = Vec::new();
        if let Some(reports) = data.get("reports").and_then(|r| r.as_array()) {
            for report in reports {
                if let Some(cats) = report.get("categories").and_then(|c| c.as_array()) {
                    for cat in cats {
                        if let Some(cat_id) = cat.as_u64() {
                            if let Some(threat_cat) = abuseipdb_category_to_threat(cat_id as u32) {
                                categories.push(threat_cat);
                            }
                        }
                    }
                }
            }
        }

        categories.sort();
        categories.dedup();

        Some(ThreatInfo {
            ip,
            score: abuse_score,
            categories,
            reports: vec![],
            sources: vec!["AbuseIPDB".to_string()],
            fetched_at: Utc::now(),
        })
    }

    async fn query_virustotal(&self, ip: IpAddr, api_key: &str) -> Option<ThreatInfo> {
        // VirusTotal API v3: https://developers.virustotal.com/reference/ip-info
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build() {
            Ok(c) => c,
            Err(_) => return None,
        };

        let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);

        let response = client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let json: serde_json::Value = response.json().await.ok()?;
        let data = json.get("data")?.get("attributes")?;

        let stats = data.get("last_analysis_stats")?;
        let malicious = stats.get("malicious")?.as_u64().unwrap_or(0);
        let suspicious = stats.get("suspicious")?.as_u64().unwrap_or(0);
        let total = malicious + suspicious +
                    stats.get("harmless")?.as_u64().unwrap_or(0) +
                    stats.get("undetected")?.as_u64().unwrap_or(0);

        if total == 0 {
            return None;
        }

        // Calculate threat score based on detection ratio
        let score = ((malicious * 100 + suspicious * 50) / total.max(1)) as u8;

        let mut categories = Vec::new();

        // Check for specific threat indicators
        if let Some(tags) = data.get("tags").and_then(|t| t.as_array()) {
            for tag in tags {
                if let Some(tag_str) = tag.as_str() {
                    match tag_str.to_lowercase().as_str() {
                        "malware" => categories.push(ThreatCategory::Malware),
                        "botnet" => categories.push(ThreatCategory::Botnet),
                        "phishing" => categories.push(ThreatCategory::Phishing),
                        "spam" => categories.push(ThreatCategory::Spam),
                        _ => {}
                    }
                }
            }
        }

        if malicious > 0 && categories.is_empty() {
            categories.push(ThreatCategory::Malware);
        }

        Some(ThreatInfo {
            ip,
            score,
            categories,
            reports: vec![],
            sources: vec!["VirusTotal".to_string()],
            fetched_at: Utc::now(),
        })
    }

    async fn query_alienvault(&self, ip: IpAddr, api_key: &str) -> Option<ThreatInfo> {
        // AlienVault OTX API: https://otx.alienvault.com/api
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build() {
            Ok(c) => c,
            Err(_) => return None,
        };

        let url = format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", ip);

        let response = client
            .get(&url)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let json: serde_json::Value = response.json().await.ok()?;

        let pulse_count = json.get("pulse_info")
            .and_then(|p| p.get("count"))
            .and_then(|c| c.as_u64())
            .unwrap_or(0);

        if pulse_count == 0 {
            return None;
        }

        // Score based on number of pulses (threat intelligence reports)
        let score = (pulse_count.min(10) * 10) as u8;

        let mut categories = Vec::new();

        if let Some(pulses) = json.get("pulse_info")
            .and_then(|p| p.get("pulses"))
            .and_then(|p| p.as_array()) {

            for pulse in pulses.iter().take(5) {
                if let Some(tags) = pulse.get("tags").and_then(|t| t.as_array()) {
                    for tag in tags {
                        if let Some(tag_str) = tag.as_str() {
                            match tag_str.to_lowercase().as_str() {
                                "malware" | "trojan" | "ransomware" => {
                                    categories.push(ThreatCategory::Malware);
                                }
                                "botnet" | "c2" | "c&c" => {
                                    categories.push(ThreatCategory::C2);
                                }
                                "phishing" => {
                                    categories.push(ThreatCategory::Phishing);
                                }
                                "scanner" | "scan" => {
                                    categories.push(ThreatCategory::Scanner);
                                }
                                "bruteforce" | "brute-force" => {
                                    categories.push(ThreatCategory::BruteForce);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        categories.sort();
        categories.dedup();

        Some(ThreatInfo {
            ip,
            score,
            categories,
            reports: vec![],
            sources: vec!["AlienVault OTX".to_string()],
            fetched_at: Utc::now(),
        })
    }

    async fn report_abuseipdb(
        &self,
        ip: IpAddr,
        category: ThreatCategory,
        comment: &str,
        api_key: &str,
    ) -> crate::Result<()> {
        // AbuseIPDB Report API: https://docs.abuseipdb.com/#report-endpoint
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| crate::RelayError::Internal(format!("HTTP client error: {}", e)))?;

        let category_id = threat_to_abuseipdb_category(category);

        let params = [
            ("ip", ip.to_string()),
            ("categories", category_id.to_string()),
            ("comment", comment.to_string()),
        ];

        let response = client
            .post("https://api.abuseipdb.com/api/v2/report")
            .header("Key", api_key)
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| crate::RelayError::Internal(format!("Report request failed: {}", e)))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(crate::RelayError::Internal(
                format!("Report failed with status: {}", response.status())
            ))
        }
    }
}

/// Threat information for an IP
#[derive(Debug, Clone)]
pub struct ThreatInfo {
    /// IP address
    pub ip: IpAddr,
    /// Threat score (0-100)
    pub score: u8,
    /// Threat categories
    pub categories: Vec<ThreatCategory>,
    /// Detailed reports
    pub reports: Vec<ThreatReport>,
    /// Feed sources
    pub sources: Vec<String>,
    /// When data was fetched
    pub fetched_at: DateTime<Utc>,
}

impl ThreatInfo {
    /// Check if this is a malicious IP
    pub fn is_malicious(&self) -> bool {
        self.score >= 80 || self.categories.iter().any(|c| c.is_malicious())
    }

    /// Check if this is a suspicious IP
    pub fn is_suspicious(&self) -> bool {
        self.score >= 40 || !self.categories.is_empty()
    }

    /// Get primary threat category
    pub fn primary_category(&self) -> Option<ThreatCategory> {
        self.categories.first().copied()
    }

    /// Get human-readable description
    pub fn description(&self) -> String {
        let cat_str = self.categories.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        
        format!("Threat score: {}%, Categories: {}", self.score, cat_str)
    }
}

/// Threat category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ThreatCategory {
    /// Malware distribution
    Malware,
    /// Command & Control server
    C2,
    /// Botnet node
    Botnet,
    /// Port scanner
    Scanner,
    /// Brute force attacker
    BruteForce,
    /// Spammer
    Spam,
    /// Phishing
    Phishing,
    /// Tor exit node
    TorExit,
    /// Proxy/VPN
    Proxy,
    /// Hosting provider
    Hosting,
    /// DDoS participant
    Ddos,
    /// Web attack
    WebAttack,
    /// SSH/FTP attack
    SshFtpAttack,
    /// SQL injection
    SqlInjection,
    /// XSS attack
    Xss,
}

impl ThreatCategory {
    /// Check if category indicates malicious activity
    pub fn is_malicious(&self) -> bool {
        matches!(self, 
            ThreatCategory::Malware |
            ThreatCategory::C2 |
            ThreatCategory::Botnet |
            ThreatCategory::Phishing |
            ThreatCategory::Ddos
        )
    }

    /// Check if category indicates suspicious but possibly legitimate activity
    pub fn is_suspicious(&self) -> bool {
        matches!(self,
            ThreatCategory::TorExit |
            ThreatCategory::Proxy |
            ThreatCategory::Hosting |
            ThreatCategory::Scanner
        )
    }
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatCategory::Malware => "Malware",
            ThreatCategory::C2 => "C2",
            ThreatCategory::Botnet => "Botnet",
            ThreatCategory::Scanner => "Scanner",
            ThreatCategory::BruteForce => "BruteForce",
            ThreatCategory::Spam => "Spam",
            ThreatCategory::Phishing => "Phishing",
            ThreatCategory::TorExit => "TorExit",
            ThreatCategory::Proxy => "Proxy",
            ThreatCategory::Hosting => "Hosting",
            ThreatCategory::Ddos => "DDoS",
            ThreatCategory::WebAttack => "WebAttack",
            ThreatCategory::SshFtpAttack => "SshFtpAttack",
            ThreatCategory::SqlInjection => "SqlInjection",
            ThreatCategory::Xss => "XSS",
        };
        write!(f, "{}", s)
    }
}

/// Individual threat report
#[derive(Debug, Clone)]
pub struct ThreatReport {
    /// Timestamp of report
    pub timestamp: DateTime<Utc>,
    /// Reporter information
    pub reporter: String,
    /// Report comment
    pub comment: String,
    /// Source feed
    pub source: String,
}

/// Threat statistics
#[derive(Debug, Clone, Default)]
pub struct ThreatStats {
    /// Total IPs checked
    pub ips_checked: u64,
    /// Threats detected
    pub threats_detected: u64,
    /// IPs auto-blocked
    pub ips_auto_blocked: u64,
    /// IPs reported by us
    pub ips_reported: u64,
    /// Feed query errors
    pub feed_errors: u64,
}

/// Threat intelligence configuration
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    /// Enable threat intelligence
    pub enabled: bool,
    /// Cache TTL
    pub cache_ttl_seconds: u64,
    /// Minimum score to block
    pub min_block_score: u8,
    /// AbuseIPDB API key
    pub abuseipdb_api_key: Option<String>,
    /// VirusTotal API key
    pub virustotal_api_key: Option<String>,
    /// AlienVault OTX API key
    pub alienvault_api_key: Option<String>,
    /// Custom feed URLs
    pub custom_feeds: Vec<String>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_ttl_seconds: 3600,
            min_block_score: 80,
            abuseipdb_api_key: None,
            virustotal_api_key: None,
            alienvault_api_key: None,
            custom_feeds: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_category() {
        assert!(ThreatCategory::Malware.is_malicious());
        assert!(ThreatCategory::C2.is_malicious());
        assert!(!ThreatCategory::TorExit.is_malicious());
        assert!(ThreatCategory::TorExit.is_suspicious());

        assert_eq!(ThreatCategory::Malware.to_string(), "Malware");
        assert_eq!(ThreatCategory::C2.to_string(), "C2");
    }

    #[test]
    fn test_threat_info() {
        let info = ThreatInfo {
            ip: "192.168.1.1".parse().unwrap(),
            score: 85,
            categories: vec![ThreatCategory::Botnet, ThreatCategory::C2],
            reports: vec![],
            sources: vec!["test".to_string()],
            fetched_at: Utc::now(),
        };

        assert!(info.is_malicious());
        assert!(info.is_suspicious());
        assert_eq!(info.primary_category(), Some(ThreatCategory::Botnet));
    }

    #[test]
    fn test_threat_feed_name() {
        let feed = ThreatFeed::AbuseIpDb {
            api_key: "test".to_string(),
        };
        assert_eq!(feed.name(), "AbuseIPDB");
        assert!(feed.supports_reporting());

        let feed2 = ThreatFeed::VirusTotal {
            api_key: "test".to_string(),
        };
        assert_eq!(feed2.name(), "VirusTotal");
        assert!(!feed2.supports_reporting());
    }

    #[tokio::test]
    async fn test_threat_intelligence_creation() {
        let ti = ThreatIntelligence::new();
        assert_eq!(ti.feeds.len(), 0);
    }

    #[tokio::test]
    async fn test_threat_intelligence_with_feeds() {
        let mut ti = ThreatIntelligence::new()
            .with_min_score(70);

        ti.add_feed(ThreatFeed::LocalBlocklist {
            entries: vec![],
        });

        assert_eq!(ti.feeds.len(), 1);
    }

    #[tokio::test]
    async fn test_local_blocklist() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let threat_info = ThreatInfo {
            ip,
            score: 100,
            categories: vec![ThreatCategory::Malware],
            reports: vec![],
            sources: vec!["local".to_string()],
            fetched_at: Utc::now(),
        };

        let feed = ThreatFeed::LocalBlocklist {
            entries: vec![(ip, threat_info.clone())],
        };

        let result = feed.query(ip).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().score, 100);
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let ti = ThreatIntelligence::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Initially no cache
        let cached = ti.get_cached(ip).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_threat_stats() {
        let ti = ThreatIntelligence::new();
        let stats = ti.get_stats().await;

        assert_eq!(stats.ips_checked, 0);
        assert_eq!(stats.threats_detected, 0);
    }

    #[test]
    fn test_category_mapping() {
        // Test AbuseIPDB category mapping
        assert_eq!(abuseipdb_category_to_threat(3), Some(ThreatCategory::BruteForce));
        assert_eq!(abuseipdb_category_to_threat(5), Some(ThreatCategory::Botnet));
        assert_eq!(abuseipdb_category_to_threat(9), Some(ThreatCategory::Malware));
        assert_eq!(abuseipdb_category_to_threat(999), None);

        // Test reverse mapping
        assert_eq!(threat_to_abuseipdb_category(ThreatCategory::BruteForce), 18);
        assert_eq!(threat_to_abuseipdb_category(ThreatCategory::Botnet), 5);
        assert_eq!(threat_to_abuseipdb_category(ThreatCategory::Malware), 9);
    }

    #[tokio::test]
    async fn test_cleanup_cache() {
        let ti = ThreatIntelligence::new();
        ti.cleanup_cache().await;
        // Should not panic
    }
}

/// Convert AbuseIPDB category ID to ThreatCategory
fn abuseipdb_category_to_threat(category_id: u32) -> Option<ThreatCategory> {
    // AbuseIPDB category IDs: https://www.abuseipdb.com/categories
    match category_id {
        3 => Some(ThreatCategory::BruteForce),      // Brute-Force
        4 => Some(ThreatCategory::WebAttack),       // Web App Attack
        5 => Some(ThreatCategory::Botnet),          // Botnet
        6 => Some(ThreatCategory::Scanner),         // Port Scan
        9 => Some(ThreatCategory::Malware),         // Malware
        10 => Some(ThreatCategory::Spam),           // Email Spam
        11 => Some(ThreatCategory::Spam),           // Blog Spam
        14 => Some(ThreatCategory::Scanner),        // Port Scan
        15 => Some(ThreatCategory::BruteForce),     // Hacking
        16 => Some(ThreatCategory::SqlInjection),   // SQL Injection
        18 => Some(ThreatCategory::BruteForce),     // Brute-Force
        19 => Some(ThreatCategory::Botnet),         // Bad Web Bot
        20 => Some(ThreatCategory::WebAttack),      // Exploited Host
        21 => Some(ThreatCategory::WebAttack),      // Web App Attack
        22 => Some(ThreatCategory::SshFtpAttack),   // SSH
        23 => Some(ThreatCategory::SshFtpAttack),   // IoT Targeted
        _ => None,
    }
}

/// Convert ThreatCategory to AbuseIPDB category ID
fn threat_to_abuseipdb_category(category: ThreatCategory) -> u32 {
    match category {
        ThreatCategory::BruteForce => 18,
        ThreatCategory::WebAttack => 21,
        ThreatCategory::Botnet => 5,
        ThreatCategory::Scanner => 14,
        ThreatCategory::Malware => 9,
        ThreatCategory::Spam => 10,
        ThreatCategory::SqlInjection => 16,
        ThreatCategory::SshFtpAttack => 22,
        ThreatCategory::Phishing => 15,
        ThreatCategory::Ddos => 4,
        ThreatCategory::Xss => 21,
        _ => 15, // Default to "Hacking"
    }
}
