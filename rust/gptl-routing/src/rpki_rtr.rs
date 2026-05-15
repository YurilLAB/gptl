//! RPKI-to-Router (RTR) protocol client per RFC 8210.
//!
//! This module replaces the previous stub `fetch_roas` that returned
//! hard-coded example data.  It opens a TCP connection to an RPKI
//! validator (e.g. Cloudflare's `rtr.rpki.cloudflare.com:8282`), sends
//! a Reset Query (PDU type 2), and reads the resulting Cache Response →
//! IPv4 Prefix / IPv6 Prefix... → End of Data stream into a vector of
//! `RoaPrefix` records the caller can validate against.
//!
//! ## PDU layout (RFC 8210 §5)
//!
//! ```text
//! +-------+----+--------+---------+
//! | Ver(1)|T(1)|Sess(2) | Len(4)  |
//! +-------+----+--------+---------+
//! | Payload (Length - 8 bytes)... |
//! +-------------------------------+
//! ```
//!
//! Type codes used here:
//!   * 2  Reset Query (we send this)
//!   * 3  Cache Response
//!   * 4  IPv4 Prefix
//!   * 6  IPv6 Prefix
//!   * 7  End of Data
//!   * 10 Error Report
//!
//! Each Prefix PDU is fixed-length (20 bytes for IPv4, 32 for IPv6) so
//! a length field mismatch is a protocol error.
//!
//! ## Scope
//!
//! This implementation supports the Reset-Query (full snapshot) path
//! only.  Incremental updates via Serial Query are not implemented —
//! the caller is expected to schedule a periodic Reset Query (typical
//! interval: ~hourly) which is what most non-router consumers do.
//!
//! ## Why not a crate?
//!
//! There IS an existing `rpki` crate, but it pulls in a huge BER /
//! cryptographic-signature dependency tree that we don't need for the
//! cache-consumer side of RTR.  RFC 8210 is small enough to implement
//! directly with `tokio::io`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Currently-supported protocol versions.  Cloudflare/RIPE/ARIN all
/// speak v1 (RFC 8210); v0 (RFC 6810) is acceptable as a fallback.
pub const RTR_VERSION_0: u8 = 0;
pub const RTR_VERSION_1: u8 = 1;

/// PDU type codes.
mod pdu {
    pub const RESET_QUERY: u8 = 2;
    pub const CACHE_RESPONSE: u8 = 3;
    pub const IPV4_PREFIX: u8 = 4;
    pub const IPV6_PREFIX: u8 = 6;
    pub const END_OF_DATA: u8 = 7;
    pub const CACHE_RESET: u8 = 8;
    pub const ROUTER_KEY: u8 = 9;
    pub const ERROR_REPORT: u8 = 10;
}

/// One ROA prefix entry returned by the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoaPrefix {
    pub prefix: IpAddr,
    pub prefix_len: u8,
    pub max_length: u8,
    pub origin_as: u32,
    /// `true` = announcement (add to cache), `false` = withdrawal.
    pub announce: bool,
}

/// Result of a full Reset-Query exchange.
#[derive(Debug, Clone)]
pub struct RtrSnapshot {
    /// RTR protocol version negotiated with the server.
    pub version: u8,
    /// Server's session ID (echoed in subsequent Serial Queries).
    pub session_id: u16,
    /// Serial number marking the snapshot.
    pub serial: u32,
    /// All prefixes returned for this snapshot.
    pub prefixes: Vec<RoaPrefix>,
}

#[derive(Debug, thiserror::Error)]
pub enum RtrError {
    #[error("connect failed: {0}")]
    Connect(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("server sent an error report (code {code}): {message}")]
    ServerError { code: u16, message: String },

    #[error("operation timed out")]
    Timeout,
}

/// Connect to `host:port`, send a Reset Query, collect the snapshot.
///
/// `overall_timeout` bounds the whole exchange end-to-end.  RPKI cache
/// snapshots are commonly 200–400k prefixes (~ 7 MB on the wire); a
/// generous default like 60s is appropriate for the first run on a
/// slow link.
pub async fn fetch_snapshot(
    host: &str,
    port: u16,
    overall_timeout: Duration,
) -> Result<RtrSnapshot, RtrError> {
    let connect_fut = async {
        let stream = TcpStream::connect((host, port))
            .await
            .map_err(|e| RtrError::Connect(format!("{}: {}", host, e)))?;
        stream
            .set_nodelay(true)
            .map_err(|e| RtrError::Io(format!("set_nodelay: {}", e)))?;
        Ok::<_, RtrError>(stream)
    };

    let stream = match tokio::time::timeout(overall_timeout, connect_fut).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(RtrError::Timeout),
    };

    match tokio::time::timeout(overall_timeout, exchange(stream)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(RtrError::Timeout),
    }
}

/// Run the Reset Query exchange on a generic stream — separated from
/// `fetch_snapshot` so unit tests can drive it with in-memory pipes.
pub async fn exchange<S>(mut stream: S) -> Result<RtrSnapshot, RtrError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ── 1. Send Reset Query (v1; fall back happens implicitly if the
    //       server replies with version 0 in its PDUs and we accept it). ──
    write_reset_query(&mut stream, RTR_VERSION_1).await?;
    stream
        .flush()
        .await
        .map_err(|e| RtrError::Io(format!("flush: {}", e)))?;

    // ── 2. Read the first PDU.  Expect Cache Response (3) or Cache
    //       Reset (8) per RFC; Error Report (10) means we failed. ──
    let mut version = 0u8;
    let mut session_id = 0u16;
    loop {
        let header = read_pdu_header(&mut stream).await?;
        match header.typ {
            pdu::CACHE_RESPONSE => {
                version = header.version;
                session_id = header.session_or_flags;
                drain_remaining(&mut stream, &header).await?;
                break;
            }
            pdu::CACHE_RESET => {
                drain_remaining(&mut stream, &header).await?;
                return Err(RtrError::Protocol(
                    "server sent Cache Reset — no snapshot available".to_string(),
                ));
            }
            pdu::ERROR_REPORT => {
                return Err(parse_error_report(&mut stream, &header).await);
            }
            other => {
                drain_remaining(&mut stream, &header).await?;
                return Err(RtrError::Protocol(format!(
                    "expected Cache Response, got PDU type {}",
                    other
                )));
            }
        }
    }

    // ── 3. Read Prefix PDUs until End Of Data. ──
    let mut prefixes = Vec::new();
    let serial: u32;
    loop {
        let header = read_pdu_header(&mut stream).await?;
        match header.typ {
            pdu::IPV4_PREFIX => {
                prefixes.push(read_ipv4_prefix(&mut stream, &header).await?);
            }
            pdu::IPV6_PREFIX => {
                prefixes.push(read_ipv6_prefix(&mut stream, &header).await?);
            }
            pdu::ROUTER_KEY => {
                // BGPSec router keys — skip silently for now (we don't
                // do BGPSec origin validation here).
                drain_remaining(&mut stream, &header).await?;
            }
            pdu::END_OF_DATA => {
                serial = read_end_of_data(&mut stream, &header).await?;
                break;
            }
            pdu::ERROR_REPORT => {
                return Err(parse_error_report(&mut stream, &header).await);
            }
            other => {
                drain_remaining(&mut stream, &header).await?;
                return Err(RtrError::Protocol(format!(
                    "unexpected PDU type {} during snapshot stream",
                    other
                )));
            }
        }
    }

    Ok(RtrSnapshot {
        version,
        session_id,
        serial,
        prefixes,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed common PDU header.  `session_or_flags` carries the raw 16-bit
/// field which is "session ID" for some PDUs and "flags / zero" for
/// others — semantics depend on the PDU type.
#[derive(Debug, Clone, Copy)]
struct PduHeader {
    version: u8,
    typ: u8,
    session_or_flags: u16,
    length: u32,
}

async fn read_pdu_header<S: AsyncRead + Unpin>(s: &mut S) -> Result<PduHeader, RtrError> {
    let mut buf = [0u8; 8];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| RtrError::Io(format!("read header: {}", e)))?;
    let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if length < 8 {
        return Err(RtrError::Protocol(format!(
            "PDU length {} smaller than header (8)",
            length
        )));
    }
    // A modestly defensive upper bound — no legitimate Prefix PDU is
    // bigger than ~32 bytes; the largest defined PDU (Router Key) is
    // 132 bytes.  16 KB lets us survive an unknown future PDU type
    // without OOMing on a malicious server.
    if length > 16 * 1024 {
        return Err(RtrError::Protocol(format!(
            "PDU length {} exceeds 16 KB cap",
            length
        )));
    }
    Ok(PduHeader {
        version: buf[0],
        typ: buf[1],
        session_or_flags: u16::from_be_bytes([buf[2], buf[3]]),
        length,
    })
}

async fn drain_remaining<S: AsyncRead + Unpin>(
    s: &mut S,
    header: &PduHeader,
) -> Result<(), RtrError> {
    let remaining = header.length.saturating_sub(8) as usize;
    if remaining == 0 {
        return Ok(());
    }
    let mut buf = vec![0u8; remaining];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| RtrError::Io(format!("drain {} bytes: {}", remaining, e)))?;
    Ok(())
}

async fn write_reset_query<S: AsyncWrite + Unpin>(s: &mut S, version: u8) -> Result<(), RtrError> {
    // Reset Query has no payload — Length = 8.
    let mut buf = [0u8; 8];
    buf[0] = version;
    buf[1] = pdu::RESET_QUERY;
    // bytes 2..4 = zero (reserved)
    buf[4..8].copy_from_slice(&8u32.to_be_bytes());
    s.write_all(&buf)
        .await
        .map_err(|e| RtrError::Io(format!("write reset query: {}", e)))
}

async fn read_ipv4_prefix<S: AsyncRead + Unpin>(
    s: &mut S,
    header: &PduHeader,
) -> Result<RoaPrefix, RtrError> {
    if header.length != 20 {
        drain_remaining(s, header).await?;
        return Err(RtrError::Protocol(format!(
            "IPv4 Prefix PDU length {} != 20",
            header.length
        )));
    }
    let mut buf = [0u8; 12];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| RtrError::Io(format!("read v4 prefix: {}", e)))?;
    let flags = buf[0];
    let prefix_len = buf[1];
    let max_length = buf[2];
    // buf[3] reserved
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    let origin_as = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Ok(RoaPrefix {
        prefix: IpAddr::V4(ip),
        prefix_len,
        max_length,
        origin_as,
        announce: (flags & 0x01) != 0,
    })
}

async fn read_ipv6_prefix<S: AsyncRead + Unpin>(
    s: &mut S,
    header: &PduHeader,
) -> Result<RoaPrefix, RtrError> {
    if header.length != 32 {
        drain_remaining(s, header).await?;
        return Err(RtrError::Protocol(format!(
            "IPv6 Prefix PDU length {} != 32",
            header.length
        )));
    }
    let mut buf = [0u8; 24];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| RtrError::Io(format!("read v6 prefix: {}", e)))?;
    let flags = buf[0];
    let prefix_len = buf[1];
    let max_length = buf[2];
    // buf[3] reserved
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[4..20]);
    let ip = Ipv6Addr::from(octets);
    let origin_as = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    Ok(RoaPrefix {
        prefix: IpAddr::V6(ip),
        prefix_len,
        max_length,
        origin_as,
        announce: (flags & 0x01) != 0,
    })
}

async fn read_end_of_data<S: AsyncRead + Unpin>(
    s: &mut S,
    header: &PduHeader,
) -> Result<u32, RtrError> {
    // Per RFC 8210, EoD in v1 carries: serial (4) + refresh (4) + retry (4) +
    // expire (4).  In v0 it carries only the serial number.
    let payload_len = header.length.saturating_sub(8) as usize;
    if payload_len < 4 {
        drain_remaining(s, header).await?;
        return Err(RtrError::Protocol("End of Data missing serial".to_string()));
    }
    let mut buf = vec![0u8; payload_len];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| RtrError::Io(format!("read EoD: {}", e)))?;
    let serial = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Ok(serial)
}

async fn parse_error_report<S: AsyncRead + Unpin>(s: &mut S, header: &PduHeader) -> RtrError {
    // session_or_flags carries the error code for Error Report PDUs.
    let code = header.session_or_flags;
    let payload_len = header.length.saturating_sub(8) as usize;
    let mut payload = vec![0u8; payload_len];
    if s.read_exact(&mut payload).await.is_err() {
        return RtrError::ServerError {
            code,
            message: "(unable to read error payload)".to_string(),
        };
    }
    // Payload layout: encapsulated_pdu_len(4) || encapsulated_pdu || msg_len(4) || msg.
    // We just extract the message — best effort.
    let mut cursor = 0usize;
    if payload.len() < cursor + 4 {
        return RtrError::ServerError {
            code,
            message: "(truncated error payload)".to_string(),
        };
    }
    let enc_len = u32::from_be_bytes([
        payload[cursor],
        payload[cursor + 1],
        payload[cursor + 2],
        payload[cursor + 3],
    ]) as usize;
    cursor += 4 + enc_len;
    if payload.len() < cursor + 4 {
        return RtrError::ServerError {
            code,
            message: String::new(),
        };
    }
    let msg_len = u32::from_be_bytes([
        payload[cursor],
        payload[cursor + 1],
        payload[cursor + 2],
        payload[cursor + 3],
    ]) as usize;
    cursor += 4;
    let end = (cursor + msg_len).min(payload.len());
    let message = String::from_utf8_lossy(&payload[cursor..end]).into_owned();
    RtrError::ServerError { code, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    // Helper: encode a PDU into raw bytes that a mock server would emit.
    fn encode_pdu(version: u8, typ: u8, sof: u16, payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u32;
        let mut out = Vec::with_capacity(8 + payload.len());
        out.push(version);
        out.push(typ);
        out.extend_from_slice(&sof.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn ipv4_prefix_payload(flags: u8, plen: u8, maxlen: u8, ip: [u8; 4], asn: u32) -> Vec<u8> {
        let mut p = vec![flags, plen, maxlen, 0];
        p.extend_from_slice(&ip);
        p.extend_from_slice(&asn.to_be_bytes());
        p
    }

    fn ipv6_prefix_payload(flags: u8, plen: u8, maxlen: u8, ip: [u8; 16], asn: u32) -> Vec<u8> {
        let mut p = vec![flags, plen, maxlen, 0];
        p.extend_from_slice(&ip);
        p.extend_from_slice(&asn.to_be_bytes());
        p
    }

    fn end_of_data_payload_v1(serial: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(16);
        p.extend_from_slice(&serial.to_be_bytes());
        // refresh / retry / expire — fake values.
        p.extend_from_slice(&3600u32.to_be_bytes());
        p.extend_from_slice(&600u32.to_be_bytes());
        p.extend_from_slice(&7200u32.to_be_bytes());
        p
    }

    /// Build a complete fake-server byte stream containing a Cache
    /// Response, two v4 prefixes, one v6 prefix, then End of Data.
    fn build_happy_path_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&encode_pdu(1, pdu::CACHE_RESPONSE, 0xABCDu16, &[]));
        s.extend_from_slice(&encode_pdu(
            1,
            pdu::IPV4_PREFIX,
            0,
            &ipv4_prefix_payload(0x01, 24, 24, [1, 0, 0, 0], 13335),
        ));
        s.extend_from_slice(&encode_pdu(
            1,
            pdu::IPV4_PREFIX,
            0,
            &ipv4_prefix_payload(0x01, 24, 24, [8, 8, 8, 0], 15169),
        ));
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        s.extend_from_slice(&encode_pdu(
            1,
            pdu::IPV6_PREFIX,
            0,
            &ipv6_prefix_payload(0x01, 32, 48, v6, 65000),
        ));
        s.extend_from_slice(&encode_pdu(
            1,
            pdu::END_OF_DATA,
            0xABCDu16,
            &end_of_data_payload_v1(42),
        ));
        s
    }

    #[tokio::test]
    async fn test_exchange_parses_cache_response_prefixes_and_eod() {
        let bytes = build_happy_path_stream();
        let (client, mut server) = duplex(8192);

        let server_task = tokio::spawn(async move {
            // Read the Reset Query the client sends.
            let mut header = [0u8; 8];
            server.read_exact(&mut header).await.unwrap();
            assert_eq!(header[1], pdu::RESET_QUERY,
                "client must send Reset Query as first PDU");
            // Stream the fake response.
            server.write_all(&bytes).await.unwrap();
            // Half-close so the client doesn't hang waiting for more.
            drop(server);
        });

        let snapshot = exchange(client).await.expect("exchange must succeed");
        server_task.await.unwrap();

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.session_id, 0xABCD);
        assert_eq!(snapshot.serial, 42);
        assert_eq!(snapshot.prefixes.len(), 3, "expected 2 v4 + 1 v6");
        let cf = &snapshot.prefixes[0];
        assert_eq!(cf.origin_as, 13335);
        assert_eq!(cf.prefix_len, 24);
        assert!(matches!(cf.prefix, IpAddr::V4(ip) if ip == Ipv4Addr::new(1, 0, 0, 0)));
        let v6 = &snapshot.prefixes[2];
        assert!(matches!(v6.prefix, IpAddr::V6(_)));
        assert_eq!(v6.origin_as, 65000);
    }

    #[tokio::test]
    async fn test_exchange_rejects_cache_reset() {
        let bytes = encode_pdu(1, pdu::CACHE_RESET, 0, &[]);
        let (client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut hdr = [0u8; 8];
            let _ = server.read_exact(&mut hdr).await;
            let _ = server.write_all(&bytes).await;
        });
        let err = exchange(client).await.unwrap_err();
        assert!(
            matches!(err, RtrError::Protocol(_)),
            "Cache Reset must surface as a Protocol error; got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_exchange_reports_server_error_pdu() {
        // Construct an Error Report PDU with code=2 ("No Data Available")
        // and message "down for maintenance".
        let message = b"down for maintenance";
        let mut payload = Vec::new();
        // Encapsulated PDU length = 0
        payload.extend_from_slice(&0u32.to_be_bytes());
        // Message length + message
        payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
        payload.extend_from_slice(message);
        let bytes = encode_pdu(1, pdu::ERROR_REPORT, 2u16, &payload);

        let (client, mut server) = duplex(256);
        tokio::spawn(async move {
            let mut hdr = [0u8; 8];
            let _ = server.read_exact(&mut hdr).await;
            let _ = server.write_all(&bytes).await;
        });
        let err = exchange(client).await.unwrap_err();
        match err {
            RtrError::ServerError { code, message } => {
                assert_eq!(code, 2);
                assert_eq!(message, "down for maintenance");
            }
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_exchange_rejects_oversized_pdu() {
        // Build a malformed PDU header with length = 100 KB to ensure the
        // parser refuses to allocate a giant buffer.
        let mut bytes = vec![1u8, pdu::CACHE_RESPONSE, 0, 0];
        bytes.extend_from_slice(&(100_000u32).to_be_bytes());
        let (client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut hdr = [0u8; 8];
            let _ = server.read_exact(&mut hdr).await;
            let _ = server.write_all(&bytes).await;
        });
        let err = exchange(client).await.unwrap_err();
        assert!(matches!(err, RtrError::Protocol(_)));
    }

    #[tokio::test]
    async fn test_exchange_rejects_short_pdu_length() {
        let mut bytes = vec![1u8, pdu::CACHE_RESPONSE, 0, 0];
        bytes.extend_from_slice(&4u32.to_be_bytes()); // length < 8
        let (client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut hdr = [0u8; 8];
            let _ = server.read_exact(&mut hdr).await;
            let _ = server.write_all(&bytes).await;
        });
        let err = exchange(client).await.unwrap_err();
        assert!(matches!(err, RtrError::Protocol(_)));
    }
}
