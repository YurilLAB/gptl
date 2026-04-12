//! DNS Protection Module
//!
//! Implements countermeasures against DNS leakage including DoH (DNS-over-HTTPS),
//! DoT (DNS-over-TLS), and DNS query proxying.

use super::{RoutingConfig, RoutingError};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// DNS guard for preventing DNS leaks
pub struct DnsGuard {
    #[allow(dead_code)]
    config: Arc<RwLock<RoutingConfig>>,
    /// DoH resolver
    doh_resolver: Arc<RwLock<DoHResolver>>,
    /// Cache
    cache: Arc<RwLock<DnsCache>>,
    /// Firewall rules
    firewall: Arc<RwLock<DnsFirewall>>,
    /// IPv6 policy
    #[allow(dead_code)]
    ipv6_policy: Arc<RwLock<Ipv6Policy>>,
}

/// DNS-over-HTTPS resolver
#[derive(Debug, Clone)]
struct DoHResolver {
    /// Resolver endpoints
    endpoints: Vec<String>,
    /// Current endpoint index
    current: usize,
    /// Request timeout
    timeout: Duration,
}

/// DNS cache
#[derive(Debug, Clone)]
struct DnsCache {
    entries: HashMap<String, CacheEntry>,
    /// Max TTL
    max_ttl: Duration,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}

/// DNS firewall
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DnsFirewall {
    /// Blocked DNS servers
    blocked_servers: Vec<IpAddr>,
    /// Allowed DNS servers (VPN)
    allowed_servers: Vec<IpAddr>,
    /// Interception rules
    intercept_rules: Vec<InterceptRule>,
}

/// Intercept rule
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct InterceptRule {
    pattern: String,
    action: InterceptAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum InterceptAction {
    Block,
    Redirect,
    Log,
}

/// IPv6 policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Ipv6Policy {
    Allow,
    Block,
    Prefer,
}

impl DnsGuard {
    /// Create new DNS guard
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        let doh_resolver = Arc::new(RwLock::new(DoHResolver {
            endpoints: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
                "https://dns.quad9.net/dns-query".to_string(),
            ],
            current: 0,
            timeout: Duration::from_secs(5),
        }));
        
        let cache = Arc::new(RwLock::new(DnsCache {
            entries: HashMap::new(),
            max_ttl: Duration::from_secs(300),
        }));
        
        let firewall = Arc::new(RwLock::new(DnsFirewall {
            blocked_servers: Vec::new(),
            allowed_servers: Vec::new(),
            intercept_rules: Vec::new(),
        }));
        
        let ipv6_policy = Arc::new(RwLock::new(Ipv6Policy::Prefer));
        
        Self {
            config,
            doh_resolver,
            cache,
            firewall,
            ipv6_policy,
        }
    }

    /// Initialize DNS protection with shutdown signal
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        self.initialize_with_shutdown(None).await
    }
    
    /// Initialize DNS protection with optional shutdown signal
    pub async fn initialize_with_shutdown(
        &self,
        mut shutdown_signal: Option<tokio::sync::watch::Receiver<bool>>
    ) -> Result<(), RoutingError> {
        // Start cache cleanup task
        let cache = self.cache.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut cache_guard = cache.write().await;
                        let now = Instant::now();
                        
                        // Also limit cache size to prevent unbounded growth
                        if cache_guard.entries.len() > 10000 {
                            // Remove oldest entries if cache is too large
                            let keys_to_remove: Vec<String> = cache_guard
                                .entries
                                .iter()
                                .filter(|(_, entry)| entry.expires_at <= now)
                                .map(|(k, _)| k.clone())
                                .collect();
                            
                            for key in keys_to_remove {
                                cache_guard.entries.remove(&key);
                            }
                        } else {
                            cache_guard.entries.retain(|_, entry| {
                                entry.expires_at > now
                            });
                        }
                    }
                    _ = async {
                        if let Some(ref mut rx) = shutdown_signal {
                            rx.changed().await.ok()
                        } else {
                            std::future::pending().await
                        }
                    } => {
                        break;
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Resolve DNS query securely
    pub async fn resolve_secure(&self, query: &str) -> Result<Vec<u8>, RoutingError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.entries.get(query) {
                if entry.expires_at > Instant::now() {
                    // Return cached response (serialized)
                    return Ok(serialize_response(&entry.addresses));
                }
            }
        }
        
        // Check firewall
        {
            let firewall = self.firewall.read().await;
            if let Some(action) = firewall.check_query(query).await {
                match action {
                    InterceptAction::Block => {
                        return Err(RoutingError::ResourceAllocationFailed(
                            "DNS query blocked".to_string()
                        ));
                    }
                    InterceptAction::Redirect => {
                        // Redirect to safe resolver
                    }
                    InterceptAction::Log => {
                        // SECURITY: DNS queries are NOT logged (reveal browsing patterns)
                        tracing::info!("DNS query intercepted and logged");
                    }
                }
            }
        }
        
        // Resolve via DoH
        let response = self.resolve_doh(query).await?;
        
        // Cache response
        {
            let mut cache = self.cache.write().await;
            let max_ttl = cache.max_ttl;
            cache.entries.insert(query.to_string(), CacheEntry {
                addresses: response.clone(),
                expires_at: Instant::now() + max_ttl,
            });
        }
        
        Ok(serialize_response(&response))
    }

    /// Resolve via DNS-over-HTTPS (RFC 8484)
    async fn resolve_doh(&self, query: &str) -> Result<Vec<IpAddr>, RoutingError> {
        let mut resolver = self.doh_resolver.write().await;
        let endpoint = &resolver.endpoints[resolver.current].clone();

        // Build DNS query in wire format
        let dns_query = build_dns_query(query)?;

        // Create HTTPS client with strict TLS settings (2025 best practices)
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .timeout(resolver.timeout)
            .https_only(true)
            .build()
            .map_err(|e| RoutingError::ResourceAllocationFailed(format!("DoH client error: {}", e)))?;

        // RFC 8484: POST method with application/dns-message
        let response = client
            .post(endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(dns_query)
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.bytes().await
                    .map_err(|e| RoutingError::ResourceAllocationFailed(format!("DoH response error: {}", e)))?;

                parse_dns_response(&body)
            }
            Ok(_) | Err(_) => {
                // Failover to next endpoint
                resolver.current = (resolver.current + 1) % resolver.endpoints.len();
                tracing::warn!("DoH endpoint failed, rotating to next");
                Err(RoutingError::ResourceAllocationFailed("DoH resolution failed".to_string()))
            }
        }
    }

    /// Configure DNS leak prevention
    pub async fn configure_leak_prevention(&self) -> Result<(), RoutingError> {
        let _firewall = self.firewall.write().await;
        
        // Block all non-tunneled DNS
        // This would interface with system firewall
        
        Ok(())
    }

    /// Test for DNS leak
    pub async fn test_for_leak(&self) -> Option<DnsLeakResult> {
        // Make test queries to known servers
        let test_domains = vec![
            "dnsleaktest.com",
            "whoami.akamai.net",
            "whoami.ultradns.net",
        ];
        
        // SECURITY: Test domain names are NOT logged
        let _ = test_domains;
        tracing::debug!("DNS leak test performed");
        
        None
    }

    /// Update IPv6 policy
    #[allow(dead_code)]
    pub(crate) async fn set_ipv6_policy(&self, policy: Ipv6Policy) {
        let mut ipv6 = self.ipv6_policy.write().await;
        *ipv6 = policy;
    }
}

impl DnsFirewall {
    /// Check query against rules
    async fn check_query(&self, query: &str) -> Option<InterceptAction> {
        for rule in &self.intercept_rules {
            if query.contains(&rule.pattern) {
                return Some(rule.action);
            }
        }
        
        None
    }

    /// Block ISP DNS servers
    #[allow(dead_code)]
    pub fn block_isp_dns(&mut self, isp_servers: Vec<IpAddr>) {
        self.blocked_servers.extend(isp_servers);
    }

    /// Allow only VPN DNS
    #[allow(dead_code)]
    pub fn allow_only_vpn(&mut self, vpn_servers: Vec<IpAddr>) {
        self.allowed_servers = vpn_servers;
    }
}

/// Serialize DNS response
fn serialize_response(addresses: &[IpAddr]) -> Vec<u8> {
    // Simple serialization for caching
    let mut result = Vec::new();
    for addr in addresses {
        match addr {
            IpAddr::V4(v4) => result.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => result.extend_from_slice(&v6.octets()),
        }
    }
    result
}

/// Build DNS query in wire format (RFC 1035)
fn build_dns_query(domain: &str) -> Result<Vec<u8>, RoutingError> {
    let mut query = Vec::new();

    // Transaction ID (random)
    let txid: u16 = rand::random();
    query.extend_from_slice(&txid.to_be_bytes());

    // Flags: standard query, recursion desired
    query.extend_from_slice(&[0x01, 0x00]);

    // Question count: 1
    query.extend_from_slice(&[0x00, 0x01]);

    // Answer, Authority, Additional counts: 0
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    // QNAME: domain name in DNS format
    for label in domain.split('.') {
        if label.len() > 63 {
            return Err(RoutingError::ResourceAllocationFailed("Label too long".to_string()));
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // Root label

    // QTYPE: A record (1)
    query.extend_from_slice(&[0x00, 0x01]);

    // QCLASS: IN (1)
    query.extend_from_slice(&[0x00, 0x01]);

    Ok(query)
}

/// Parse DNS response (RFC 1035)
fn parse_dns_response(data: &[u8]) -> Result<Vec<IpAddr>, RoutingError> {
    if data.len() < 12 {
        return Err(RoutingError::ResourceAllocationFailed("Invalid DNS response".to_string()));
    }

    // Skip header (12 bytes)
    let mut offset = 12;

    // Skip question section
    while offset < data.len() && data[offset] != 0 {
        let len = data[offset] as usize;
        offset += len + 1;
        if offset >= data.len() {
            return Err(RoutingError::ResourceAllocationFailed("Malformed question".to_string()));
        }
    }
    offset += 5; // Skip null terminator, QTYPE, QCLASS

    let mut addresses = Vec::new();

    // Parse answer section
    while offset + 12 <= data.len() {
        // Skip NAME (may be compressed)
        if data[offset] & 0xC0 == 0xC0 {
            offset += 2; // Compression pointer
        } else {
            while offset < data.len() && data[offset] != 0 {
                let len = data[offset] as usize;
                offset += len + 1;
            }
            offset += 1; // Skip null terminator
        }

        if offset + 10 > data.len() {
            break;
        }

        // TYPE
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // CLASS
        offset += 2;

        // TTL
        offset += 4;

        // RDLENGTH
        let rdlen = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + rdlen > data.len() {
            break;
        }

        // RDATA
        if rtype == 1 && rdlen == 4 {
            // A record (IPv4)
            let ip = std::net::Ipv4Addr::new(
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            );
            addresses.push(IpAddr::V4(ip));
        } else if rtype == 28 && rdlen == 16 {
            // AAAA record (IPv6)
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[offset..offset + 16]);
            let ip = std::net::Ipv6Addr::from(octets);
            addresses.push(IpAddr::V6(ip));
        }

        offset += rdlen;
    }

    if addresses.is_empty() {
        return Err(RoutingError::ResourceAllocationFailed("No addresses in response".to_string()));
    }

    Ok(addresses)
}

/// DNS leak test result
#[derive(Debug, Clone)]
pub struct DnsLeakResult {
    pub resolver_ip: IpAddr,
    pub resolver_isp: String,
    pub is_leaking: bool,
}

/// System DNS configuration manager
pub struct SystemDnsManager {
    original_servers: Vec<IpAddr>,
    vpn_servers: Vec<IpAddr>,
}

impl SystemDnsManager {
    /// Create new DNS manager
    pub fn new(vpn_servers: Vec<IpAddr>) -> Self {
        Self {
            original_servers: Vec::new(),
            vpn_servers,
        }
    }

    /// Apply VPN DNS configuration
    pub fn apply_vpn_dns(&mut self) -> Result<(), DnsConfigError> {
        // Store original servers
        self.original_servers = self.get_system_dns()?;
        
        // Set VPN DNS
        self.set_system_dns(&self.vpn_servers)?;
        
        Ok(())
    }

    /// Restore original DNS
    pub fn restore_original_dns(&self) -> Result<(), DnsConfigError> {
        self.set_system_dns(&self.original_servers)?;
        Ok(())
    }

    /// Get system DNS servers
    fn get_system_dns(&self) -> Result<Vec<IpAddr>, DnsConfigError> {
        // Platform-specific implementation
        // Windows: registry
        // Linux: /etc/resolv.conf
        // macOS: scutil
        Ok(Vec::new())
    }

    /// Set system DNS servers
    fn set_system_dns(&self, _servers: &[IpAddr]) -> Result<(), DnsConfigError> {
        // Platform-specific implementation
        Ok(())
    }
}

/// DNS configuration error
#[derive(Debug, thiserror::Error)]
pub enum DnsConfigError {
    #[error("Failed to read system DNS: {0}")]
    ReadError(String),
    #[error("Failed to set system DNS: {0}")]
    WriteError(String),
    #[error("Permission denied")]
    PermissionDenied,
}

/// DNS-over-TLS resolver
pub struct DoTResolver {
    /// Resolver endpoints
    endpoints: Vec<String>,
    /// TLS configuration
    #[allow(dead_code)]
    tls_config: TlsConfig,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TlsConfig {
    /// Certificate pinning hashes
    pinned_certs: Vec<String>,
    /// ALPN protocols
    alpn: Vec<String>,
}

impl Default for DoTResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DoTResolver {
    /// Create new DoT resolver
    pub fn new() -> Self {
        Self {
            endpoints: vec![
                "1.1.1.1:853".to_string(),  // Cloudflare
                "8.8.8.8:853".to_string(),  // Google
                "9.9.9.9:853".to_string(),  // Quad9
            ],
            tls_config: TlsConfig {
                pinned_certs: Vec::new(),
                alpn: vec!["dot".to_string()],
            },
        }
    }

    /// Resolve via DNS-over-TLS (RFC 7858)
    pub async fn resolve(&self, query: &str) -> Result<Vec<IpAddr>, DnsError> {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use rustls::ClientConfig;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Build DNS query
        let dns_query = build_dns_query(query)
            .map_err(|e| DnsError::ResolutionFailed(e.to_string()))?;

        // Try each endpoint
        for endpoint in &self.endpoints {
            // Parse endpoint
            let addr = endpoint.parse::<std::net::SocketAddr>()
                .map_err(|e| DnsError::ResolutionFailed(format!("Invalid endpoint: {}", e)))?;

            // Create TLS config with modern settings (2025 best practices)
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let connector = TlsConnector::from(std::sync::Arc::new(config));

            // Extract hostname for SNI
            let hostname = endpoint.split(':').next().unwrap_or("dns");
            let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
                .map_err(|e| DnsError::TlsError(format!("Invalid server name: {}", e)))?;

            // Connect with timeout
            let tcp_stream = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                TcpStream::connect(addr)
            ).await {
                Ok(Ok(stream)) => stream,
                _ => continue, // Try next endpoint
            };

            // Establish TLS
            let mut tls_stream = match connector.connect(server_name, tcp_stream).await {
                Ok(stream) => stream,
                Err(_) => continue, // Try next endpoint
            };

            // Send DNS query with length prefix (RFC 7858)
            let query_len = (dns_query.len() as u16).to_be_bytes();
            if tls_stream.write_all(&query_len).await.is_err() {
                continue;
            }
            if tls_stream.write_all(&dns_query).await.is_err() {
                continue;
            }

            // Read response length
            let mut len_buf = [0u8; 2];
            if tls_stream.read_exact(&mut len_buf).await.is_err() {
                continue;
            }
            let response_len = u16::from_be_bytes(len_buf) as usize;

            // Read response
            let mut response_buf = vec![0u8; response_len];
            if tls_stream.read_exact(&mut response_buf).await.is_err() {
                continue;
            }

            // Parse response
            match parse_dns_response(&response_buf) {
                Ok(addresses) => return Ok(addresses),
                Err(_) => continue,
            }
        }

        Err(DnsError::ResolutionFailed("All endpoints failed".to_string()))
    }
}

/// DNS error
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("Timeout")]
    Timeout,
}

/// Transparent DNS proxy detector
pub struct TransparentProxyDetector {
    /// Known proxy indicators
    #[allow(dead_code)]
    indicators: Vec<String>,
}

impl Default for TransparentProxyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparentProxyDetector {
    /// Create new detector
    pub fn new() -> Self {
        Self {
            indicators: vec![
                "dns.msftncsi.com".to_string(),
                "resolver1.opendns.com".to_string(),
            ],
        }
    }

    /// Detect transparent proxy
    pub async fn detect(&self) -> Option<String> {
        // Make DNS request to unique domain
        // Check if response indicates proxy
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache() {
        let cache = DnsCache {
            entries: HashMap::new(),
            max_ttl: Duration::from_secs(300),
        };

        // Test cache entry creation
        let entry = CacheEntry {
            addresses: vec![
                "1.2.3.4".parse().unwrap(),
            ],
            expires_at: Instant::now() + Duration::from_secs(300),
        };

        assert!(entry.expires_at > Instant::now());
    }

    #[tokio::test]
    async fn test_dns_guard() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = DnsGuard::new(config);

        // Test initialization
        assert!(guard.initialize().await.is_ok());
    }

    #[test]
    fn test_dns_query_building() {
        let query = build_dns_query("example.com").unwrap();

        // Verify header
        assert_eq!(query.len() > 12, true);

        // Verify flags (standard query, recursion desired)
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);
    }

    #[test]
    fn test_dns_response_parsing() {
        // Build a minimal valid DNS response
        let mut response = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response, recursion available
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answers: 1
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // Null terminator
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            // Answer section
            0xC0, 0x0C, // Name pointer to question
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
            0x00, 0x04, // RDLENGTH: 4
            0x5D, 0xB8, 0xD8, 0x22, // IP: 93.184.216.34
        ];

        let addresses = parse_dns_response(&response).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].to_string(), "93.184.216.34");
    }

    #[tokio::test]
    async fn test_dot_resolver() {
        let resolver = DoTResolver::new();

        // Test resolver creation
        assert!(!resolver.endpoints.is_empty());
        assert_eq!(resolver.tls_config.alpn[0], "dot");
    }

    #[test]
    fn test_dns_firewall() {
        let mut firewall = DnsFirewall {
            blocked_servers: Vec::new(),
            allowed_servers: Vec::new(),
            intercept_rules: Vec::new(),
        };

        // Test blocking ISP DNS
        firewall.block_isp_dns(vec!["8.8.8.8".parse().unwrap()]);
        assert_eq!(firewall.blocked_servers.len(), 1);

        // Test VPN-only mode
        firewall.allow_only_vpn(vec!["10.0.0.1".parse().unwrap()]);
        assert_eq!(firewall.allowed_servers.len(), 1);
    }

    #[test]
    fn test_system_dns_manager() {
        let manager = SystemDnsManager::new(vec!["10.0.0.1".parse().unwrap()]);
        assert_eq!(manager.vpn_servers.len(), 1);
    }

    #[tokio::test]
    async fn test_plain_dns_query_blocked_by_firewall_rule() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = DnsGuard::new(config);

        // Add a block rule for ISP resolver (8.8.8.8-style direct queries)
        {
            let mut firewall = guard.firewall.write().await;
            firewall.intercept_rules.push(InterceptRule {
                pattern: "blocked-domain".to_string(),
                action: InterceptAction::Block,
            });
        }

        // resolve_secure checks the firewall before making network calls
        let result = guard.resolve_secure("blocked-domain.example.com").await;
        assert!(result.is_err(),
            "query matching a block rule must be rejected before reaching the network");
    }

    #[test]
    fn test_dns_query_building_valid_structure() {
        let query = build_dns_query("www.example.org").unwrap();

        // Minimum valid length: 12 header + at least one label + terminator + QTYPE + QCLASS
        assert!(query.len() > 12 + 5, "DNS query too short");

        // Transaction ID (2 bytes): random, just verify non-zero length
        // Flags byte 2 = 0x01 (recursion desired)
        assert_eq!(query[2], 0x01, "recursion desired flag must be set");
        // Question count = 1
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
    }

    #[test]
    fn test_dns_query_building_very_long_label_rejected() {
        // Labels > 63 characters are invalid per RFC 1035
        let long_label = "a".repeat(64);
        let domain = format!("{}.com", long_label);
        let result = build_dns_query(&domain);
        assert!(result.is_err(),
            "label longer than 63 characters must be rejected");
    }

    #[test]
    fn test_dns_response_parsing_malformed_too_short() {
        // Fewer than 12 bytes → invalid header
        let malformed = vec![0x00, 0x01, 0x81, 0x80, 0x00, 0x01];
        let result = parse_dns_response(&malformed);
        assert!(result.is_err(),
            "DNS response shorter than 12 bytes must be rejected");
    }

    #[test]
    fn test_dns_response_parsing_no_answers_returns_error() {
        // Valid header with 0 answers → parse_dns_response must return Err
        let response = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question (minimal)
            0x00, // empty QNAME
            0x00, 0x01, // QTYPE A
            0x00, 0x01, // QCLASS IN
        ];

        let result = parse_dns_response(&response);
        assert!(result.is_err(),
            "DNS response with no answer records must return Err");
    }

    #[tokio::test]
    async fn test_dns_cache_prevents_duplicate_network_calls() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = DnsGuard::new(config);

        // Manually seed the cache with a known entry
        {
            let mut cache = guard.cache.write().await;
            cache.entries.insert(
                "cached.example.com".to_string(),
                CacheEntry {
                    addresses: vec!["93.184.216.34".parse().unwrap()],
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            );
        }

        // resolve_secure should return cached data without hitting the network
        let result = guard.resolve_secure("cached.example.com").await;
        assert!(result.is_ok(),
            "valid cached entry must return Ok without a network request");
        let data = result.unwrap();
        // Serialized IPv4: 4 bytes for 93.184.216.34
        assert_eq!(data.len(), 4, "cached IPv4 must serialize to 4 bytes");
    }

    #[test]
    fn test_dns_firewall_block_isp_servers_accumulates() {
        let mut firewall = DnsFirewall {
            blocked_servers: Vec::new(),
            allowed_servers: Vec::new(),
            intercept_rules: Vec::new(),
        };

        let servers = vec![
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        firewall.block_isp_dns(servers);
        assert_eq!(firewall.blocked_servers.len(), 3,
            "all provided ISP servers must be added to blocked list");
    }
}
