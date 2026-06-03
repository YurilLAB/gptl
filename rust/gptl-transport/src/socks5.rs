//! SOCKS5 server (RFC 1928) for the GPTL client proxy.
//!
//! Supports:
//!   - No-auth method (0x00) — suitable because we're listening on localhost only
//!   - CONNECT command (0x01)
//!   - IPv4 (0x01), domain name (0x03), and IPv6 (0x04) address types
//!
//! Usage: accept a TCP connection, call `negotiate` to handle the SOCKS5 handshake.
//! The caller receives the `ConnectRequest` and is responsible for establishing
//! the upstream circuit connection and splicing data.

use crate::TransportError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// The destination requested by the SOCKS5 client.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectRequest {
    /// Destination hostname or IP
    pub host: String,
    /// Destination port
    pub port: u16,
}

/// SOCKS5 reply codes (RFC 1928 §6).
#[repr(u8)]
enum ReplyCode {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressNotSupported = 0x08,
}

/// Perform the complete SOCKS5 negotiation on `stream`.
///
/// Returns `ConnectRequest` on success. The caller must then:
///   1. Establish the upstream connection (through a circuit).
///   2. Call `send_success` or `send_failure` to complete the SOCKS5 handshake.
pub async fn negotiate(stream: &mut TcpStream) -> Result<ConnectRequest, TransportError> {
    // ── Phase 1: method negotiation ───────────────────────────────────────────
    // Client: VER(1) NMETHODS(1) METHODS(N)
    let ver = stream.read_u8().await.map_err(io_err)?;
    if ver != 0x05 {
        return Err(TransportError::Socks5(format!(
            "unsupported SOCKS version {}",
            ver
        )));
    }
    let n_methods = stream.read_u8().await.map_err(io_err)? as usize;
    if n_methods == 0 {
        return Err(TransportError::Socks5("client sent zero methods".into()));
    }
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await.map_err(io_err)?;

    // We only support NO_AUTH (0x00)
    if !methods.contains(&0x00) {
        // Tell client: no acceptable methods
        stream.write_all(&[0x05, 0xFF]).await.map_err(io_err)?;
        return Err(TransportError::Socks5(
            "client offered no supported auth methods".into(),
        ));
    }
    // Select NO_AUTH
    stream.write_all(&[0x05, 0x00]).await.map_err(io_err)?;

    // ── Phase 2: request ──────────────────────────────────────────────────────
    // Client: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DSTPORT(2)
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(io_err)?;

    if header[0] != 0x05 {
        return Err(TransportError::Socks5("version mismatch in request".into()));
    }
    if header[1] != 0x01 {
        // Only CONNECT is supported
        send_reply(stream, ReplyCode::CommandNotSupported).await;
        return Err(TransportError::Socks5(format!(
            "unsupported command 0x{:02x}",
            header[1]
        )));
    }
    // header[2] is RSV — ignored

    let (host, port) = match header[3] {
        0x01 => {
            // IPv4 (4 bytes)
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.map_err(io_err)?;
            let port = stream.read_u16().await.map_err(io_err)?;
            (format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]), port)
        }
        0x03 => {
            // Domain name: len(1) + name
            let len = stream.read_u8().await.map_err(io_err)? as usize;
            if len == 0 {
                send_reply(stream, ReplyCode::GeneralFailure).await;
                return Err(TransportError::Socks5("zero-length domain name".into()));
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await.map_err(io_err)?;
            let port = stream.read_u16().await.map_err(io_err)?;
            let host = String::from_utf8(name)
                .map_err(|_| TransportError::Socks5("non-UTF-8 domain name".into()))?;
            (host, port)
        }
        0x04 => {
            // IPv6 (16 bytes)
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.map_err(io_err)?;
            let port = stream.read_u16().await.map_err(io_err)?;
            let addr = std::net::Ipv6Addr::from(ip);
            (format!("[{}]", addr), port)
        }
        atyp => {
            send_reply(stream, ReplyCode::AddressNotSupported).await;
            return Err(TransportError::Socks5(format!(
                "unsupported address type 0x{:02x}",
                atyp
            )));
        }
    };

    if port == 0 {
        send_reply(stream, ReplyCode::GeneralFailure).await;
        return Err(TransportError::Socks5("port 0 is not valid".into()));
    }

    Ok(ConnectRequest { host, port })
}

/// Send a SOCKS5 success reply (call this when the upstream connection is established).
pub async fn send_success(stream: &mut TcpStream) {
    send_reply(stream, ReplyCode::Succeeded).await;
}

/// Send a SOCKS5 failure reply (call this when the upstream connection failed).
pub async fn send_connection_refused(stream: &mut TcpStream) {
    send_reply(stream, ReplyCode::ConnectionRefused).await;
}

/// Send a SOCKS5 failure reply for general errors.
pub async fn send_general_failure(stream: &mut TcpStream) {
    send_reply(stream, ReplyCode::GeneralFailure).await;
}

async fn send_reply(stream: &mut TcpStream, code: ReplyCode) {
    // REP format: VER RSV REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    // We bind to 0.0.0.0:0 since we're a proxy
    let reply = [
        0x05,       // VER
        code as u8, // REP
        0x00,       // RSV
        0x01,       // ATYP: IPv4
        0, 0, 0, 0, // BND.ADDR: 0.0.0.0
        0, 0, // BND.PORT: 0
    ];
    if let Err(e) = stream.write_all(&reply).await {
        debug!("SOCKS5 send_reply: write failed: {}", e);
    }
}

fn io_err(e: std::io::Error) -> TransportError {
    TransportError::Io(format!("SOCKS5 I/O: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Simulate a client sending a SOCKS5 request and return the ConnectRequest.
    async fn client_sends(client_bytes: Vec<u8>) -> Result<ConnectRequest, TransportError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server task
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            negotiate(&mut stream).await
        });

        // Client sends raw bytes then waits for reply (enough for negotiation)
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&client_bytes).await.unwrap();

        server.await.unwrap()
    }

    /// Fuzz: the SOCKS5 server negotiation must never panic on arbitrary or
    /// truncated client input — only return Ok/Err. The client closes after
    /// sending so a short read hits EOF instead of hanging; negotiate is also
    /// wrapped in a timeout as a backstop.
    #[tokio::test]
    async fn fuzz_socks5_negotiate_never_panics() {
        use std::time::Duration;
        let mut state: u64 = 0xA5A5_1234_DEAD_0001;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..250 {
            let len = (next() % 72) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ =
                    tokio::time::timeout(Duration::from_millis(500), negotiate(&mut stream)).await;
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            let _ = client.write_all(&bytes).await;
            let _ = client.shutdown().await;
            drop(client);
            let _ = server.await;
        }
    }

    fn socks5_domain_request(domain: &str, port: u16) -> Vec<u8> {
        let mut buf = vec![
            0x05,
            0x01,
            0x00, // VER NMETHODS METHODS[NO_AUTH]
            0x05,
            0x01,
            0x00,
            0x03, // VER CMD RSV ATYP=domain
            domain.len() as u8,
        ];
        buf.extend_from_slice(domain.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    fn socks5_ipv4_request(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut buf = vec![
            0x05, 0x01, 0x00, // negotiation
            0x05, 0x01, 0x00, 0x01, // CONNECT, IPv4
        ];
        buf.extend_from_slice(&ip);
        buf.extend_from_slice(&port.to_be_bytes());
        buf
    }

    #[tokio::test]
    async fn test_domain_connect_request_parsed() {
        let bytes = socks5_domain_request("example.com", 443);
        let req = client_sends(bytes).await.unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
    }

    #[tokio::test]
    async fn test_ipv4_connect_request_parsed() {
        let bytes = socks5_ipv4_request([93, 184, 216, 34], 80);
        let req = client_sends(bytes).await.unwrap();
        assert_eq!(req.host, "93.184.216.34");
        assert_eq!(req.port, 80);
    }

    #[tokio::test]
    async fn test_unsupported_socks_version_rejected() {
        let bytes = vec![0x04, 0x01, 0x00]; // SOCKS4
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_no_acceptable_auth_method_rejected() {
        // Client only offers USERNAME/PASSWORD (0x02)
        let bytes = vec![
            0x05, 0x01, 0x02, // VER NMETHODS METHODS[USERNAME_PASSWORD]
        ];
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_associate_command_rejected() {
        let mut bytes = vec![
            0x05, 0x01, 0x00, // negotiation
            0x05, 0x03, 0x00, 0x01, // CMD=UDP ASSOCIATE
        ];
        bytes.extend_from_slice(&[0, 0, 0, 0]); // addr
        bytes.extend_from_slice(&[0, 80]); // port
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unsupported_address_type_rejected() {
        let bytes = vec![
            0x05, 0x01, 0x00, // negotiation
            0x05, 0x01, 0x00, 0x02, // ATYP=0x02 (invalid)
            0, 0, 0, 0, 0, 80,
        ];
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_zero_port_rejected() {
        let bytes = socks5_ipv4_request([127, 0, 0, 1], 0);
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_zero_length_domain_rejected() {
        let bytes = vec![
            0x05, 0x01, 0x00, // negotiation
            0x05, 0x01, 0x00, 0x03, // ATYP=domain
            0x00, // len=0
            0x01, 0xBB, // port 443
        ];
        let result = client_sends(bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_max_domain_length() {
        // 255 chars — the SOCKS5 max domain length
        let long_domain = "a".repeat(255);
        let bytes = socks5_domain_request(&long_domain, 80);
        let req = client_sends(bytes).await.unwrap();
        assert_eq!(req.host.len(), 255);
    }

    #[tokio::test]
    async fn test_high_port_number() {
        let bytes = socks5_ipv4_request([10, 0, 0, 1], 65535);
        let req = client_sends(bytes).await.unwrap();
        assert_eq!(req.port, 65535);
    }

    #[tokio::test]
    async fn test_multiple_auth_methods_picks_no_auth() {
        // Client offers both USERNAME/PASSWORD and NO_AUTH
        let mut buf = vec![
            0x05, 0x02, 0x02, 0x00, // VER NMETHODS METHODS[UP, NO_AUTH]
            0x05, 0x01, 0x00, 0x03, // CONNECT domain
            7u8,
        ];
        buf.extend_from_slice(b"foo.com");
        buf.extend_from_slice(&443u16.to_be_bytes());
        let req = client_sends(buf).await.unwrap();
        assert_eq!(req.host, "foo.com");
    }

    #[tokio::test]
    async fn test_ipv6_connect_request_parsed() {
        let mut buf = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&8080u16.to_be_bytes());
        let req = client_sends(buf).await.unwrap();
        assert_eq!(req.host, "[::1]");
        assert_eq!(req.port, 8080);
    }

    #[tokio::test]
    async fn test_send_connection_refused_writes_socks5_reply_5() {
        // Regression: on relay-side rejection (exit policy violation, DNS
        // failure), the proxy must emit a SOCKS5 reply byte with REP=0x05
        // before closing.  Otherwise curl reports
        // "Failed to receive SOCKS response, proxy closed connection."
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            send_connection_refused(&mut stream).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        // Format: VER(05) REP(?) RSV(00) ATYP(01 = IPv4) BND.ADDR(4) BND.PORT(2)
        assert_eq!(buf[0], 0x05, "VER must be 5");
        assert_eq!(buf[1], 0x05, "REP must be 0x05 (ConnectionRefused)");
        assert_eq!(buf[2], 0x00, "RSV must be 0");
        assert_eq!(buf[3], 0x01, "ATYP must be IPv4");
    }

    #[tokio::test]
    async fn test_send_general_failure_writes_socks5_reply_1() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            send_general_failure(&mut stream).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        server.await.unwrap();

        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 0x05);
        assert_eq!(buf[1], 0x01, "REP must be 0x01 (GeneralFailure)");
    }

    #[tokio::test]
    async fn test_ipv6_full_address_parsed() {
        let mut buf = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04];
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let req = client_sends(buf).await.unwrap();
        assert_eq!(req.host, "[2001:db8::1]");
        assert_eq!(req.port, 443);
    }
}
