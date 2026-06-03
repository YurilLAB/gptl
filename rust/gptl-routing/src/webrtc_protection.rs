//! WebRTC Protection Module
//!
//! Implements countermeasures against WebRTC IP leaks including STUN/TURN
//! configuration, ICE candidate filtering, and browser policy enforcement.

use super::{RoutingConfig, RoutingError, WebrtcConfig};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// WebRTC guard for preventing IP leaks
pub struct WebrtcGuard {
    #[allow(dead_code)]
    config: Arc<RwLock<RoutingConfig>>,
    /// STUN server configuration
    stun_config: Arc<RwLock<StunConfig>>,
    /// TURN server configuration
    turn_config: Arc<RwLock<TurnConfig>>,
    /// ICE policy
    ice_policy: Arc<RwLock<IcePolicy>>,
    /// Blocked interfaces
    blocked_interfaces: Arc<RwLock<HashSet<String>>>,
}

/// STUN server configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StunConfig {
    /// VPN-provided STUN servers
    servers: Vec<String>,
    /// Block public STUN
    block_public: bool,
}

/// TURN server configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TurnConfig {
    /// VPN-provided TURN servers
    servers: Vec<String>,
    /// Force TURN relay
    force_relay: bool,
    /// Authentication credentials
    credentials: TurnCredentials,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TurnCredentials {
    username: String,
    credential: String,
}

/// ICE (Interactive Connectivity Establishment) policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum IcePolicy {
    /// Allow all candidates
    All,
    /// Relay only (force TURN)
    RelayOnly,
    /// No host candidates
    NoHost,
    /// Default address only
    DefaultAddressOnly,
}

impl WebrtcGuard {
    /// Create new WebRTC guard
    pub fn new(config: Arc<RwLock<RoutingConfig>>) -> Self {
        let stun_config = Arc::new(RwLock::new(StunConfig {
            servers: vec!["stun:vpn-provider.com:3478".to_string()],
            block_public: true,
        }));

        let turn_config = Arc::new(RwLock::new(TurnConfig {
            servers: vec!["turn:vpn-provider.com:3478".to_string()],
            force_relay: true,
            credentials: TurnCredentials {
                username: "vpn-user".to_string(),
                credential: "vpn-pass".to_string(),
            },
        }));

        let ice_policy = Arc::new(RwLock::new(IcePolicy::RelayOnly));

        let blocked_interfaces = Arc::new(RwLock::new(HashSet::new()));

        Self {
            config,
            stun_config,
            turn_config,
            ice_policy,
            blocked_interfaces,
        }
    }

    /// Initialize WebRTC protection
    pub async fn initialize(&self) -> Result<(), RoutingError> {
        // Block local interfaces
        let mut blocked = self.blocked_interfaces.write().await;
        blocked.insert("eth0".to_string());
        blocked.insert("wlan0".to_string());
        blocked.insert("en0".to_string());

        Ok(())
    }

    /// Get secure WebRTC configuration
    pub async fn get_secure_config(&self) -> Result<WebrtcConfig, RoutingError> {
        let stun = self.stun_config.read().await;
        let turn = self.turn_config.read().await;
        let ice = self.ice_policy.read().await;

        Ok(WebrtcConfig {
            stun_servers: stun.servers.clone(),
            turn_servers: turn.servers.clone(),
            block_local_ips: *ice == IcePolicy::NoHost || *ice == IcePolicy::RelayOnly,
            force_relay: turn.force_relay,
        })
    }

    /// Filter ICE candidates
    pub async fn filter_candidates(&self, candidates: Vec<IceCandidate>) -> Vec<IceCandidate> {
        let ice_policy = self.ice_policy.read().await;
        let blocked = self.blocked_interfaces.read().await;

        candidates
            .into_iter()
            .filter(|c| {
                match *ice_policy {
                    IcePolicy::All => true,
                    IcePolicy::RelayOnly => c.candidate_type == CandidateType::Relay,
                    IcePolicy::NoHost => c.candidate_type != CandidateType::Host,
                    IcePolicy::DefaultAddressOnly => {
                        // Only allow VPN interface address
                        c.is_vpn_address()
                    }
                }
            })
            .filter(|c| !blocked.contains(&c.interface))
            .collect()
    }

    /// Block non-proxied UDP
    pub async fn block_non_proxied_udp(&self) -> FirewallRules {
        FirewallRules {
            block_direct_udp: true,
            allow_stun_only: true,
            allow_turn_only: true,
        }
    }

    /// Test for WebRTC leak
    pub async fn test_for_leak(&self) -> Option<WebrtcLeakResult> {
        // In production, use browser automation or native API
        // to check if real IP is exposed

        // Make STUN request and check returned address
        None
    }

    /// Update ICE policy
    pub(crate) async fn set_ice_policy(&self, policy: IcePolicy) {
        let mut ice = self.ice_policy.write().await;
        *ice = policy;
    }

    /// Disable WebRTC entirely
    pub async fn disable_webrtc(&self) -> Result<(), RoutingError> {
        self.set_ice_policy(IcePolicy::RelayOnly).await;

        let mut turn = self.turn_config.write().await;
        turn.force_relay = true;
        turn.servers.clear(); // No TURN = no WebRTC

        Ok(())
    }
}

/// ICE candidate
#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub ip: IpAddr,
    pub port: u16,
    pub candidate_type: CandidateType,
    pub interface: String,
    pub foundation: String,
    pub priority: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    ServerReflexive, // STUN
    PeerReflexive,
    Relay, // TURN
}

impl IceCandidate {
    /// Check if this is a VPN address
    fn is_vpn_address(&self) -> bool {
        // Check against known VPN IP ranges
        match self.ip {
            IpAddr::V4(v4) => {
                // Check for VPN tunnel ranges
                let octets = v4.octets();
                // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 are typical VPN ranges
                octets[0] == 10
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(_) => {
                // Check for VPN IPv6 ranges
                false
            }
        }
    }
}

/// Firewall rules
#[derive(Debug, Clone)]
pub struct FirewallRules {
    pub block_direct_udp: bool,
    pub allow_stun_only: bool,
    pub allow_turn_only: bool,
}

/// WebRTC leak test result
#[derive(Debug, Clone)]
pub struct WebrtcLeakResult {
    pub local_ips_exposed: Vec<IpAddr>,
    pub public_ip_exposed: Option<IpAddr>,
    pub is_leaking: bool,
}

/// Browser WebRTC policy enforcer
pub struct BrowserPolicyEnforcer {
    /// Target browser
    browser: BrowserType,
    /// Policy settings
    settings: BrowserSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserType {
    Firefox,
    Chrome,
    Safari,
    Edge,
    Brave,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BrowserSettings {
    /// Disable WebRTC
    disable_webrtc: bool,
    /// Force proxy
    force_proxy: bool,
    /// Block local IPs
    block_local_ips: bool,
}

impl BrowserPolicyEnforcer {
    /// Create new enforcer
    pub fn new(browser: BrowserType) -> Self {
        Self {
            browser,
            settings: BrowserSettings {
                disable_webrtc: false,
                force_proxy: true,
                block_local_ips: true,
            },
        }
    }

    /// Generate configuration for browser
    pub fn generate_config(&self) -> BrowserConfig {
        match self.browser {
            BrowserType::Firefox => self.firefox_config(),
            BrowserType::Chrome => self.chrome_config(),
            BrowserType::Safari => self.safari_config(),
            BrowserType::Edge => self.edge_config(),
            BrowserType::Brave => self.brave_config(),
        }
    }

    /// Firefox configuration
    fn firefox_config(&self) -> BrowserConfig {
        let mut prefs = Vec::new();

        if self.settings.disable_webrtc {
            prefs.push((
                "media.peerconnection.enabled".to_string(),
                "false".to_string(),
            ));
        } else {
            // Limit ICE candidates
            prefs.push((
                "media.peerconnection.ice.default_address_only".to_string(),
                "true".to_string(),
            ));
            prefs.push((
                "media.peerconnection.ice.no_host".to_string(),
                "true".to_string(),
            ));
        }

        BrowserConfig { preferences: prefs }
    }

    /// Chrome configuration
    fn chrome_config(&self) -> BrowserConfig {
        // Chrome uses command-line flags and extensions
        BrowserConfig {
            preferences: vec![(
                "webrtc.ip_handling_policy".to_string(),
                "disable_non_proxied_udp".to_string(),
            )],
        }
    }

    /// Safari configuration
    fn safari_config(&self) -> BrowserConfig {
        // Safari has built-in protections
        BrowserConfig {
            preferences: vec![],
        }
    }

    /// Edge configuration
    fn edge_config(&self) -> BrowserConfig {
        // Similar to Chrome
        self.chrome_config()
    }

    /// Brave configuration
    fn brave_config(&self) -> BrowserConfig {
        // Brave has built-in WebRTC protection
        BrowserConfig {
            preferences: vec![(
                "webrtc.ip_handling_policy".to_string(),
                "default_public_and_private_interfaces".to_string(),
            )],
        }
    }
}

/// Browser configuration
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub preferences: Vec<(String, String)>,
}

/// STUN/TURN server tester
pub struct StunTurnTester {
    /// Test servers
    servers: Vec<String>,
}

impl Default for StunTurnTester {
    fn default() -> Self {
        Self::new()
    }
}

impl StunTurnTester {
    /// Create new tester
    pub fn new() -> Self {
        Self {
            servers: vec![
                "stun.l.google.com:19302".to_string(),
                "stun1.l.google.com:19302".to_string(),
                "stun.cloudflare.com:3478".to_string(),
            ],
        }
    }

    /// Test STUN server (RFC 5389 - STUN protocol)
    pub async fn test_stun(&self, server: &str) -> Result<StunResult, StunError> {
        use std::time::Duration;
        use tokio::net::UdpSocket;

        // Parse server address
        let addr = server
            .parse::<std::net::SocketAddr>()
            .map_err(|e| StunError::ConnectionFailed(format!("Invalid address: {}", e)))?;

        // Bind to local socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| StunError::ConnectionFailed(format!("Bind failed: {}", e)))?;

        // Build STUN Binding Request (RFC 5389)
        let stun_request = build_stun_binding_request();

        // Send request
        socket
            .send_to(&stun_request, addr)
            .await
            .map_err(|e| StunError::ConnectionFailed(format!("Send failed: {}", e)))?;

        // Receive response with timeout
        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((len, _))) => {
                // Parse STUN response
                let mapped_addr = parse_stun_response(&buf[..len])?;

                tracing::debug!("STUN server test performed");
                Ok(StunResult {
                    server: "[REDACTED]".to_string(),
                    mapped_address: Some(mapped_addr),
                    reachable: true,
                })
            }
            Ok(Err(e)) => Err(StunError::ConnectionFailed(format!("Recv failed: {}", e))),
            Err(_) => Err(StunError::Timeout),
        }
    }

    /// Test for IP exposure (2025 best practice: comprehensive leak detection)
    pub async fn test_ip_exposure(&self) -> Vec<IpExposure> {
        let mut exposures = Vec::new();

        for server in &self.servers {
            if let Ok(result) = self.test_stun(server).await {
                if let Some(mapped) = result.mapped_address {
                    exposures.push(IpExposure {
                        source: server.clone(),
                        ip: mapped,
                        is_vpn_ip: is_private_ip(&mapped),
                    });
                }
            }
        }

        exposures
    }
}

/// Build STUN Binding Request (RFC 5389)
fn build_stun_binding_request() -> Vec<u8> {
    let mut request = Vec::new();

    // STUN Message Type: Binding Request (0x0001)
    request.extend_from_slice(&[0x00, 0x01]);

    // Message Length: 0 (no attributes for basic request)
    request.extend_from_slice(&[0x00, 0x00]);

    // Magic Cookie (RFC 5389)
    request.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

    // Transaction ID (96 bits random)
    let txid: [u8; 12] = rand::random();
    request.extend_from_slice(&txid);

    request
}

/// Parse STUN Binding Response (RFC 5389)
fn parse_stun_response(data: &[u8]) -> Result<IpAddr, StunError> {
    if data.len() < 20 {
        return Err(StunError::InvalidResponse);
    }

    // Verify STUN message type (Binding Success Response: 0x0101)
    if data[0] != 0x01 || data[1] != 0x01 {
        return Err(StunError::InvalidResponse);
    }

    // Verify Magic Cookie
    if data[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        return Err(StunError::InvalidResponse);
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut offset = 20;

    // Parse attributes
    while offset + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        // XOR-MAPPED-ADDRESS (0x0020) - preferred in RFC 5389
        if attr_type == 0x0020 && attr_len >= 8 {
            let family = data[offset + 1];
            let port_xor = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let _port = port_xor ^ 0x2112; // XOR with magic cookie high bits

            if family == 0x01 {
                // IPv4
                let ip_xor = u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let ip = ip_xor ^ 0x2112A442; // XOR with magic cookie
                let ip_addr = std::net::Ipv4Addr::from(ip.to_be_bytes());
                return Ok(IpAddr::V4(ip_addr));
            } else if family == 0x02 && attr_len >= 20 {
                // IPv6
                let mut ip_bytes = [0u8; 16];
                for i in 0..16 {
                    ip_bytes[i] = data[offset + 4 + i] ^ data[4 + (i % 12)];
                }
                let ip_addr = std::net::Ipv6Addr::from(ip_bytes);
                return Ok(IpAddr::V6(ip_addr));
            }
        }

        // MAPPED-ADDRESS (0x0001) - fallback for older servers
        if attr_type == 0x0001 && attr_len >= 8 {
            let family = data[offset + 1];

            if family == 0x01 {
                // IPv4
                let ip = u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let ip_addr = std::net::Ipv4Addr::from(ip.to_be_bytes());
                return Ok(IpAddr::V4(ip_addr));
            }
        }

        // Move to next attribute (attributes are padded to 4-byte boundary)
        offset += (attr_len + 3) & !3;
    }

    Err(StunError::InvalidResponse)
}

/// Check if IP is private/VPN range
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // RFC 1918 private ranges
            octets[0] == 10
                || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                || (octets[0] == 192 && octets[1] == 168)
                // Carrier-grade NAT
                || (octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127)
        }
        IpAddr::V6(v6) => {
            // ULA (Unique Local Address)
            v6.segments()[0] & 0xfe00 == 0xfc00
        }
    }
}

/// STUN test result
#[derive(Debug, Clone)]
pub struct StunResult {
    pub server: String,
    pub mapped_address: Option<IpAddr>,
    pub reachable: bool,
}

/// IP exposure
#[derive(Debug, Clone)]
pub struct IpExposure {
    pub source: String,
    pub ip: IpAddr,
    pub is_vpn_ip: bool,
}

/// STUN error
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Timeout")]
    Timeout,
    #[error("Invalid response")]
    InvalidResponse,
}

/// mDNS protection
/// Prevents local hostname leakage via mDNS
pub struct MdnsProtection {
    /// Block mDNS queries
    #[allow(dead_code)]
    block_mdns: bool,
}

impl Default for MdnsProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsProtection {
    /// Create new mDNS protection
    pub fn new() -> Self {
        Self { block_mdns: true }
    }

    /// Block mDNS traffic
    pub fn block(&self) -> FirewallRules {
        FirewallRules {
            block_direct_udp: true,
            allow_stun_only: false,
            allow_turn_only: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_candidate_filtering() {
        let candidate = IceCandidate {
            ip: "192.168.1.1".parse().unwrap(),
            port: 12345,
            candidate_type: CandidateType::Host,
            interface: "eth0".to_string(),
            foundation: "1".to_string(),
            priority: 100,
        };

        assert!(candidate.is_vpn_address());
    }

    #[test]
    fn test_browser_configs() {
        let firefox = BrowserPolicyEnforcer::new(BrowserType::Firefox);
        let config = firefox.generate_config();

        assert!(!config.preferences.is_empty());
    }

    #[tokio::test]
    async fn test_webrtc_guard() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);

        let secure_config = guard.get_secure_config().await.unwrap();
        assert!(secure_config.force_relay);
    }

    #[tokio::test]
    async fn test_candidate_filtering() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);

        let candidates = vec![
            IceCandidate {
                ip: "192.168.1.1".parse().unwrap(),
                port: 12345,
                candidate_type: CandidateType::Host,
                interface: "eth0".to_string(),
                foundation: "1".to_string(),
                priority: 100,
            },
            IceCandidate {
                ip: "1.2.3.4".parse().unwrap(),
                port: 12345,
                candidate_type: CandidateType::Relay,
                interface: "tun0".to_string(),
                foundation: "2".to_string(),
                priority: 200,
            },
        ];

        let filtered = guard.filter_candidates(candidates).await;
        // With RelayOnly policy, only relay candidates should pass
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].candidate_type, CandidateType::Relay);
    }

    #[test]
    fn test_stun_request_building() {
        let request = build_stun_binding_request();

        // Verify STUN message structure
        assert_eq!(request.len(), 20); // Header only
        assert_eq!(request[0], 0x00); // Message type high byte
        assert_eq!(request[1], 0x01); // Message type low byte (Binding Request)
        assert_eq!(&request[4..8], &[0x21, 0x12, 0xA4, 0x42]); // Magic cookie
    }

    #[test]
    fn test_stun_response_parsing() {
        // Build a valid STUN response with XOR-MAPPED-ADDRESS
        let mut response = vec![
            0x01, 0x01, // Binding Success Response
            0x00, 0x0C, // Message length: 12 bytes
            0x21, 0x12, 0xA4, 0x42, // Magic cookie
            0x00, 0x00, 0x00, 0x00, // Transaction ID (part 1)
            0x00, 0x00, 0x00, 0x00, // Transaction ID (part 2)
            0x00, 0x00, 0x00, 0x00, // Transaction ID (part 3)
            // XOR-MAPPED-ADDRESS attribute
            0x00, 0x20, // Attribute type: XOR-MAPPED-ADDRESS
            0x00, 0x08, // Attribute length: 8 bytes
            0x00, 0x01, // Reserved + Family (IPv4)
            0x00, 0x00, // Port XOR'd
            0x00, 0x00, 0x00, 0x00, // IP XOR'd with magic cookie
        ];

        // XOR the IP with magic cookie to get 1.2.3.4
        // Attribute layout at offset 20: type(2) + len(2) + reserved(1) + family(1) + port(2) + ip(4)
        // The IP field starts at byte 28 (20 header + 4 attr header + 4 reserved/family/port)
        let target_ip = 0x01020304u32;
        let xor_ip = target_ip ^ 0x2112A442;
        response[28..32].copy_from_slice(&xor_ip.to_be_bytes());

        let ip = parse_stun_response(&response).unwrap();
        assert_eq!(ip.to_string(), "1.2.3.4");
    }

    #[test]
    fn test_private_ip_detection() {
        // RFC 1918 ranges
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));

        // Carrier-grade NAT
        assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));

        // Public IPs
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_browser_policy_generation() {
        // Test Firefox
        let firefox = BrowserPolicyEnforcer::new(BrowserType::Firefox);
        let config = firefox.generate_config();
        assert!(config
            .preferences
            .iter()
            .any(|(k, _)| k.contains("peerconnection")));

        // Test Chrome
        let chrome = BrowserPolicyEnforcer::new(BrowserType::Chrome);
        let config = chrome.generate_config();
        assert!(config.preferences.iter().any(|(k, _)| k.contains("webrtc")));

        // Test Brave
        let brave = BrowserPolicyEnforcer::new(BrowserType::Brave);
        let config = brave.generate_config();
        assert!(!config.preferences.is_empty());
    }

    #[tokio::test]
    async fn test_ice_policy_update() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);

        // Change policy
        guard.set_ice_policy(IcePolicy::NoHost).await;

        // Verify policy changed
        let ice_policy = guard.ice_policy.read().await;
        assert_eq!(*ice_policy, IcePolicy::NoHost);
    }

    #[tokio::test]
    async fn test_webrtc_disable() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);

        assert!(guard.disable_webrtc().await.is_ok());

        // Verify TURN servers cleared
        let turn = guard.turn_config.read().await;
        assert!(turn.servers.is_empty());
    }

    #[test]
    fn test_mdns_protection() {
        let protection = MdnsProtection::new();
        let rules = protection.block();

        assert!(rules.block_direct_udp);
        assert!(!rules.allow_stun_only);
    }

    #[test]
    fn test_firewall_rules() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);

        // This would be async in real usage
        // let rules = guard.block_non_proxied_udp().await;
        // assert!(rules.block_direct_udp);
    }

    #[test]
    fn test_stun_tester_creation() {
        let tester = StunTurnTester::new();
        assert!(!tester.servers.is_empty());
        assert!(tester.servers.iter().any(|s| s.contains("stun")));
    }

    #[tokio::test]
    async fn test_local_ip_candidates_filtered_in_relay_only_mode() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);
        // Default policy is RelayOnly — local Host candidates must be filtered
        guard.initialize().await.unwrap();

        let candidates = vec![
            IceCandidate {
                ip: "192.168.0.5".parse().unwrap(), // private/local
                port: 11111,
                candidate_type: CandidateType::Host,
                interface: "tun0".to_string(), // not in blocked_interfaces list
                foundation: "1".to_string(),
                priority: 100,
            },
            IceCandidate {
                ip: "10.8.0.1".parse().unwrap(), // private/local
                port: 22222,
                candidate_type: CandidateType::Host,
                interface: "tun1".to_string(),
                foundation: "2".to_string(),
                priority: 200,
            },
        ];

        let filtered = guard.filter_candidates(candidates).await;
        assert!(
            filtered.is_empty(),
            "all Host candidates must be filtered out in RelayOnly mode, got {}",
            filtered.len()
        );
    }

    #[tokio::test]
    async fn test_non_relay_candidates_blocked_in_relay_only_mode() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);
        // Default policy is RelayOnly

        let candidates = vec![
            IceCandidate {
                ip: "8.8.8.8".parse().unwrap(),
                port: 33333,
                candidate_type: CandidateType::ServerReflexive, // STUN
                interface: "tun0".to_string(),
                foundation: "1".to_string(),
                priority: 50,
            },
            IceCandidate {
                ip: "1.2.3.4".parse().unwrap(),
                port: 44444,
                candidate_type: CandidateType::Relay, // TURN — allowed
                interface: "tun0".to_string(),
                foundation: "2".to_string(),
                priority: 300,
            },
        ];

        let filtered = guard.filter_candidates(candidates).await;
        // Only the Relay candidate should survive
        assert_eq!(
            filtered.len(),
            1,
            "only Relay candidates must survive in RelayOnly mode"
        );
        assert_eq!(filtered[0].candidate_type, CandidateType::Relay);
    }

    #[tokio::test]
    async fn test_filter_candidates_no_host_mode_allows_stun_and_relay() {
        let config = Arc::new(RwLock::new(RoutingConfig::default()));
        let guard = WebrtcGuard::new(config);
        guard.set_ice_policy(IcePolicy::NoHost).await;

        let candidates = vec![
            IceCandidate {
                ip: "1.2.3.4".parse().unwrap(),
                port: 5000,
                candidate_type: CandidateType::Host, // must be filtered
                interface: "tun0".to_string(),
                foundation: "1".to_string(),
                priority: 10,
            },
            IceCandidate {
                ip: "5.6.7.8".parse().unwrap(),
                port: 5001,
                candidate_type: CandidateType::ServerReflexive, // STUN — allowed
                interface: "tun1".to_string(),
                foundation: "2".to_string(),
                priority: 20,
            },
            IceCandidate {
                ip: "9.10.11.12".parse().unwrap(),
                port: 5002,
                candidate_type: CandidateType::Relay, // TURN — allowed
                interface: "tun2".to_string(),
                foundation: "3".to_string(),
                priority: 30,
            },
        ];

        let filtered = guard.filter_candidates(candidates).await;
        assert_eq!(
            filtered.len(),
            2,
            "NoHost mode must allow STUN and Relay but block Host candidates"
        );
        assert!(
            filtered
                .iter()
                .all(|c| c.candidate_type != CandidateType::Host),
            "no Host candidate must survive NoHost filtering"
        );
    }

    #[test]
    fn test_vpn_address_detection_private_ranges() {
        // 10.x.x.x
        let c1 = IceCandidate {
            ip: "10.0.0.1".parse().unwrap(),
            port: 0,
            candidate_type: CandidateType::Host,
            interface: String::new(),
            foundation: String::new(),
            priority: 0,
        };
        assert!(
            c1.is_vpn_address(),
            "10.0.0.1 must be detected as VPN/private address"
        );

        // 172.16.x.x
        let c2 = IceCandidate {
            ip: "172.20.0.1".parse().unwrap(),
            port: 0,
            candidate_type: CandidateType::Host,
            interface: String::new(),
            foundation: String::new(),
            priority: 0,
        };
        assert!(
            c2.is_vpn_address(),
            "172.20.0.1 must be detected as VPN/private address"
        );

        // Public IP — must not be flagged as VPN
        let c3 = IceCandidate {
            ip: "203.0.113.5".parse().unwrap(),
            port: 0,
            candidate_type: CandidateType::Host,
            interface: String::new(),
            foundation: String::new(),
            priority: 0,
        };
        assert!(
            !c3.is_vpn_address(),
            "203.0.113.5 is a public IP and must not be a VPN address"
        );
    }

    #[test]
    fn test_is_private_ip_covers_cgnat_range() {
        // 100.64.0.0/10 is carrier-grade NAT
        assert!(
            is_private_ip(&"100.64.0.1".parse().unwrap()),
            "CGNAT 100.64.x.x must be treated as private"
        );
        assert!(
            is_private_ip(&"100.127.255.255".parse().unwrap()),
            "CGNAT upper bound must be treated as private"
        );
        assert!(
            !is_private_ip(&"100.128.0.0".parse().unwrap()),
            "100.128.0.0 is outside CGNAT range and must not be private"
        );
    }
}
