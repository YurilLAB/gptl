//! Wire-format cell encoding and decoding.
//!
//! All cells are fixed 512 bytes to resist traffic-size analysis.
//! Layout:
//!   [0..4]   circuit_id  (u32, big-endian)
//!   [4]      cell_type   (u8)
//!   [5..512] payload     (507 bytes, zero-padded)
//!
//! # Phase 2 multi-hop extension
//!
//! Two-hop circuits use `CellType::RelayInner` when relay1 forwards inner
//! encrypted data to relay2. The inner cell is encrypted to a smaller 486-byte
//! ciphertext (fitting inside a RELAY_FORWARD data field), which relay2 decrypts
//! using its own session keys without needing relay1's keys at all.

use crate::TransportError;

/// Fixed cell size in bytes.
pub const CELL_SIZE: usize = 512;
/// Payload bytes per cell.
pub const CELL_PAYLOAD_LEN: usize = 507;

// ── Relay cell size constants ─────────────────────────────────────────────────

/// Inner relay plaintext length (full RELAY cells, single-hop or exit hop).
/// 507 payload − 16 Poly1305 tag = 491 bytes of plaintext.
pub const RELAY_PLAINTEXT_LEN: usize = 491;
/// Inner relay cell header: cmd(1) + stream_id(2) + data_len(2) = 5 bytes.
pub const RELAY_HEADER_LEN: usize = 5;
/// Maximum data bytes in a single-hop RELAY cell.
pub const RELAY_MAX_DATA: usize = RELAY_PLAINTEXT_LEN - RELAY_HEADER_LEN; // 486

// ── Phase 2: inner-hop relay cell constants ───────────────────────────────────
// Two-hop circuit cells need to fit inside the RELAY_MAX_DATA (486-byte) data
// field of the outer RELAY_FORWARD cell, leaving room for the inner AEAD tag.

/// Inner-hop ciphertext length: must fit in RELAY_MAX_DATA.
pub const RELAY_INNER_CT_LEN: usize = RELAY_MAX_DATA; // 486
/// Inner-hop plaintext length: ciphertext − 16 byte Poly1305 tag.
pub const RELAY_INNER_PLAINTEXT_LEN: usize = RELAY_INNER_CT_LEN - 16; // 470
/// Maximum data bytes in an inner-hop relay cell.
pub const RELAY_INNER_MAX_DATA: usize = RELAY_INNER_PLAINTEXT_LEN - RELAY_HEADER_LEN; // 465

/// Cell command codes, sent in the cell header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    /// No-op / keepalive padding
    Padding = 0,
    /// Client → relay: initiate X25519 handshake
    Create = 1,
    /// Relay → client: handshake response + key confirmation
    Created = 2,
    /// Encrypted relay data (outer layer, single-hop or first-hop)
    Relay = 3,
    /// Tear down a circuit
    Destroy = 4,
    /// IP/version information exchange (first cell after TCP connect)
    Netinfo = 5,
    /// Inner relay cell for Phase 2 multi-hop (relay1 → relay2).
    /// Payload: inner_ct[486] || padding[21].
    RelayInner = 6,
}

impl CellType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Padding),
            1 => Some(Self::Create),
            2 => Some(Self::Created),
            3 => Some(Self::Relay),
            4 => Some(Self::Destroy),
            5 => Some(Self::Netinfo),
            6 => Some(Self::RelayInner),
            _ => None,
        }
    }
}

/// A fixed-size 512-byte protocol cell.
#[derive(Clone)]
pub struct Cell {
    /// Identifies which circuit this cell belongs to (0 = no circuit / control)
    pub circuit_id: u32,
    /// Cell command
    pub cell_type: CellType,
    /// Payload (always 507 bytes; trailing bytes are zero-padded)
    pub payload: [u8; CELL_PAYLOAD_LEN],
}

impl Cell {
    /// Create a new cell with a zeroed payload.
    pub fn new(circuit_id: u32, cell_type: CellType) -> Self {
        Self {
            circuit_id,
            cell_type,
            payload: [0u8; CELL_PAYLOAD_LEN],
        }
    }

    /// Build a wire-level PADDING cell with a uniformly-random payload.
    /// Using random bytes (not zeros) prevents trivial pattern matching that
    /// would otherwise let a passive observer distinguish padding from real
    /// encrypted traffic by payload content.
    pub fn padding(circuit_id: u32) -> Self {
        use rand::RngCore;
        let mut payload = [0u8; CELL_PAYLOAD_LEN];
        rand::thread_rng().fill_bytes(&mut payload);
        Self {
            circuit_id,
            cell_type: CellType::Padding,
            payload,
        }
    }

    /// Serialize to exactly 512 bytes.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut out = [0u8; CELL_SIZE];
        out[0..4].copy_from_slice(&self.circuit_id.to_be_bytes());
        out[4] = self.cell_type as u8;
        out[5..CELL_SIZE].copy_from_slice(&self.payload);
        out
    }

    /// Deserialize from exactly 512 bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Result<Self, TransportError> {
        let circuit_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let cell_type = CellType::from_u8(buf[4]).ok_or_else(|| {
            TransportError::Protocol(format!("unknown cell type 0x{:02x}", buf[4]))
        })?;
        let mut payload = [0u8; CELL_PAYLOAD_LEN];
        payload.copy_from_slice(&buf[5..CELL_SIZE]);
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
        })
    }

    /// Return a read-only view of the first `n` payload bytes.
    pub fn payload_slice(&self, n: usize) -> &[u8] {
        &self.payload[..n.min(CELL_PAYLOAD_LEN)]
    }
}

impl std::fmt::Debug for Cell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cell")
            .field("circuit_id", &self.circuit_id)
            .field("cell_type", &self.cell_type)
            .field("payload_preview", &&self.payload[..8])
            .finish()
    }
}

// ── RELAY inner cell ──────────────────────────────────────────────────────────

/// Commands carried inside an encrypted RELAY or RelayInner cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    // ── Stream commands ───────────────────────────────────────────────────────
    /// Ask relay to connect to a target host:port
    Begin = 1,
    /// Forward raw data on a stream
    Data = 2,
    /// Close a stream (clean EOF)
    End = 3,
    /// Relay successfully connected to the target
    Connected = 4,
    /// Relay failed to connect to the target
    BeginFailed = 5,

    // ── Phase 2: Circuit extension commands ───────────────────────────────────
    /// Client → relay1: extend circuit to next hop.
    ///
    /// Payload layout (all big-endian):
    ///   [0..4]       addr_len: u32 — length of the "ip:port" string
    ///   [4..4+N]     addr: UTF-8 "ip:port" string
    ///   [4+N..4+N+32]  next-relay fingerprint (SHA-256 of static pubkey)
    ///   [4+N+32..4+N+64] client ephemeral X25519 pubkey for next hop
    ///   [4+N+64..4+N+96] client nonce (random 32 bytes) for next hop
    Extend = 10,

    /// relay1 → client: circuit extension succeeded.
    ///
    /// Payload (96 bytes):
    ///   [0..32]  next-relay ephemeral X25519 pubkey
    ///   [32..64] next-relay nonce
    ///   [64..96] key confirmation = HMAC-SHA256(forward_key, "gptl-v1-confirm")
    Extended = 11,

    /// relay1 → client: circuit extension failed.
    /// Payload: UTF-8 reason string.
    ExtendFailed = 12,

    /// relay1 → relay2 (or relay1 → client on return path): forward inner
    /// encrypted data for the next hop.
    ///
    /// stream_id = 0 (circuit-level).
    /// data = RELAY_INNER_CT_LEN (486) bytes — the inner ciphertext.
    Forward = 13,
}

impl RelayCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Begin),
            2 => Some(Self::Data),
            3 => Some(Self::End),
            4 => Some(Self::Connected),
            5 => Some(Self::BeginFailed),
            10 => Some(Self::Extend),
            11 => Some(Self::Extended),
            12 => Some(Self::ExtendFailed),
            13 => Some(Self::Forward),
            _ => None,
        }
    }
}

/// Decoded inner relay cell (parsed from the plaintext of an encrypted RELAY cell).
#[derive(Debug, Clone)]
pub struct RelayCell {
    pub command: RelayCommand,
    pub stream_id: u16,
    pub data: Vec<u8>,
}

impl RelayCell {
    // ── Single-hop (outer relay1) encoding ───────────────────────────────────

    /// Encode into a `RELAY_PLAINTEXT_LEN` (491-byte) buffer.
    /// This buffer is then encrypted by the relay1 cipher into a 507-byte payload.
    pub fn encode(&self) -> Result<[u8; RELAY_PLAINTEXT_LEN], TransportError> {
        if self.data.len() > RELAY_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "relay data too large: {} > {} bytes",
                self.data.len(),
                RELAY_MAX_DATA
            )));
        }
        let mut buf = [0u8; RELAY_PLAINTEXT_LEN];
        buf[0] = self.command as u8;
        buf[1..3].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[3..5].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf[5..5 + self.data.len()].copy_from_slice(&self.data);
        Ok(buf)
    }

    /// Decode from a `RELAY_PLAINTEXT_LEN` (491-byte) decrypted buffer.
    pub fn decode(buf: &[u8; RELAY_PLAINTEXT_LEN]) -> Result<Self, TransportError> {
        let command = RelayCommand::from_u8(buf[0]).ok_or_else(|| {
            TransportError::Protocol(format!("unknown relay command 0x{:02x}", buf[0]))
        })?;
        let stream_id = u16::from_be_bytes([buf[1], buf[2]]);
        let data_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if data_len > RELAY_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "relay inner data_len {} exceeds maximum {}",
                data_len, RELAY_MAX_DATA
            )));
        }
        Ok(Self {
            command,
            stream_id,
            data: buf[5..5 + data_len].to_vec(),
        })
    }

    // ── Phase 2 inner-hop encoding ────────────────────────────────────────────

    /// Encode into a `RELAY_INNER_PLAINTEXT_LEN` (470-byte) buffer.
    /// This is encrypted into a 486-byte inner ciphertext that fits inside the
    /// outer `Forward` relay cell's data field.
    pub fn encode_inner(&self) -> Result<[u8; RELAY_INNER_PLAINTEXT_LEN], TransportError> {
        if self.data.len() > RELAY_INNER_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "inner relay data too large: {} > {} bytes (2-hop limit)",
                self.data.len(),
                RELAY_INNER_MAX_DATA
            )));
        }
        let mut buf = [0u8; RELAY_INNER_PLAINTEXT_LEN];
        buf[0] = self.command as u8;
        buf[1..3].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[3..5].copy_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf[5..5 + self.data.len()].copy_from_slice(&self.data);
        Ok(buf)
    }

    /// Decode from a `RELAY_INNER_PLAINTEXT_LEN` (470-byte) decrypted buffer.
    pub fn decode_inner(buf: &[u8; RELAY_INNER_PLAINTEXT_LEN]) -> Result<Self, TransportError> {
        let command = RelayCommand::from_u8(buf[0]).ok_or_else(|| {
            TransportError::Protocol(format!("unknown relay command 0x{:02x}", buf[0]))
        })?;
        let stream_id = u16::from_be_bytes([buf[1], buf[2]]);
        let data_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if data_len > RELAY_INNER_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "inner relay data_len {} exceeds maximum {}",
                data_len, RELAY_INNER_MAX_DATA
            )));
        }
        Ok(Self {
            command,
            stream_id,
            data: buf[5..5 + data_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_roundtrip() {
        let mut cell = Cell::new(42, CellType::Relay);
        cell.payload[0] = 0xAB;
        cell.payload[506] = 0xCD;
        let bytes = cell.to_bytes();
        assert_eq!(bytes.len(), CELL_SIZE);
        let decoded = Cell::from_bytes(&bytes.try_into().unwrap()).unwrap();
        assert_eq!(decoded.circuit_id, 42);
        assert!(matches!(decoded.cell_type, CellType::Relay));
        assert_eq!(decoded.payload[0], 0xAB);
        assert_eq!(decoded.payload[506], 0xCD);
    }

    #[test]
    fn test_cell_circuit_id_zero() {
        let cell = Cell::new(0, CellType::Padding);
        let bytes = cell.to_bytes();
        let decoded = Cell::from_bytes(&bytes.try_into().unwrap()).unwrap();
        assert_eq!(decoded.circuit_id, 0);
    }

    #[test]
    fn test_cell_circuit_id_max() {
        let cell = Cell::new(u32::MAX, CellType::Destroy);
        let bytes = cell.to_bytes();
        let decoded = Cell::from_bytes(&bytes.try_into().unwrap()).unwrap();
        assert_eq!(decoded.circuit_id, u32::MAX);
    }

    #[test]
    fn test_cell_unknown_type_rejected() {
        let mut buf = [0u8; CELL_SIZE];
        buf[4] = 0xFF;
        assert!(matches!(
            Cell::from_bytes(&buf).unwrap_err(),
            TransportError::Protocol(_)
        ));
    }

    #[test]
    fn test_all_cell_types_roundtrip() {
        for ct in [
            CellType::Padding,
            CellType::Create,
            CellType::Created,
            CellType::Relay,
            CellType::Destroy,
            CellType::Netinfo,
            CellType::RelayInner,
        ] {
            let cell = Cell::new(1, ct);
            let decoded = Cell::from_bytes(&cell.to_bytes().try_into().unwrap()).unwrap();
            assert_eq!(decoded.cell_type as u8, ct as u8);
        }
    }

    #[test]
    fn test_cell_size_is_512() {
        assert_eq!(Cell::new(1, CellType::Padding).to_bytes().len(), 512);
    }

    #[test]
    fn test_relay_cell_roundtrip() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 7,
            data: b"hello world".to_vec(),
        };
        let decoded = RelayCell::decode(&inner.encode().unwrap()).unwrap();
        assert_eq!(decoded.stream_id, 7);
        assert_eq!(decoded.data, b"hello world");
    }

    #[test]
    fn test_relay_cell_max_data() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 1,
            data: vec![0xAA; RELAY_MAX_DATA],
        };
        assert!(inner.encode().is_ok());
    }

    #[test]
    fn test_relay_cell_overflow_rejected() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 1,
            data: vec![0; RELAY_MAX_DATA + 1],
        };
        assert!(inner.encode().is_err());
    }

    #[test]
    fn test_relay_cell_empty_data() {
        let inner = RelayCell {
            command: RelayCommand::End,
            stream_id: 0,
            data: vec![],
        };
        let decoded = RelayCell::decode(&inner.encode().unwrap()).unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_relay_cell_unknown_command_rejected() {
        let mut buf = [0u8; RELAY_PLAINTEXT_LEN];
        buf[0] = 0xFF;
        assert!(RelayCell::decode(&buf).is_err());
    }

    #[test]
    fn test_relay_cell_data_len_overflow_rejected() {
        let mut buf = [0u8; RELAY_PLAINTEXT_LEN];
        buf[0] = RelayCommand::Data as u8;
        let bad_len = (RELAY_MAX_DATA + 100) as u16;
        buf[3..5].copy_from_slice(&bad_len.to_be_bytes());
        assert!(RelayCell::decode(&buf).is_err());
    }

    // ── Phase 2 inner-hop tests ───────────────────────────────────────────────

    #[test]
    fn test_inner_cell_roundtrip() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 3,
            data: b"inner hop data".to_vec(),
        };
        let encoded = inner.encode_inner().unwrap();
        let decoded = RelayCell::decode_inner(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 3);
        assert_eq!(decoded.data, b"inner hop data");
    }

    #[test]
    fn test_inner_cell_max_data() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 1,
            data: vec![0xBB; RELAY_INNER_MAX_DATA],
        };
        assert!(inner.encode_inner().is_ok());
    }

    #[test]
    fn test_inner_cell_overflow_rejected() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 1,
            data: vec![0; RELAY_INNER_MAX_DATA + 1],
        };
        assert!(inner.encode_inner().is_err());
    }

    #[test]
    fn test_inner_plaintext_smaller_than_outer() {
        // Inner must be smaller to fit in outer data field after AEAD encryption.
        assert!(RELAY_INNER_PLAINTEXT_LEN < RELAY_PLAINTEXT_LEN);
        // Inner ciphertext must fit exactly in the outer data field.
        assert_eq!(RELAY_INNER_CT_LEN, RELAY_MAX_DATA);
    }

    #[test]
    fn test_phase2_relay_commands_roundtrip() {
        for &cmd in &[
            RelayCommand::Extend,
            RelayCommand::Extended,
            RelayCommand::ExtendFailed,
            RelayCommand::Forward,
        ] {
            assert_eq!(RelayCommand::from_u8(cmd as u8), Some(cmd));
        }
    }

    #[test]
    fn test_relay_inner_unknown_command_rejected() {
        let mut buf = [0u8; RELAY_INNER_PLAINTEXT_LEN];
        buf[0] = 0xFE;
        assert!(RelayCell::decode_inner(&buf).is_err());
    }

    #[test]
    fn test_cell_payload_is_zero_padded_by_default() {
        let cell = Cell::new(1, CellType::Relay);
        assert!(cell.payload.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_relay_cell_all_commands_roundtrip() {
        for &cmd in &[
            RelayCommand::Begin,
            RelayCommand::Data,
            RelayCommand::End,
            RelayCommand::Connected,
            RelayCommand::BeginFailed,
            RelayCommand::Extend,
            RelayCommand::Extended,
            RelayCommand::ExtendFailed,
            RelayCommand::Forward,
        ] {
            let cell = RelayCell {
                command: cmd,
                stream_id: 42,
                data: b"test-payload".to_vec(),
            };
            let encoded = cell.encode().unwrap();
            let decoded = RelayCell::decode(&encoded).unwrap();
            assert_eq!(decoded.command, cmd);
            assert_eq!(decoded.stream_id, 42);
            assert_eq!(decoded.data, b"test-payload");
        }
    }

    #[test]
    fn test_relay_cell_stream_id_boundaries() {
        for &sid in &[0u16, 1, u16::MAX] {
            let cell = RelayCell {
                command: RelayCommand::Data,
                stream_id: sid,
                data: vec![0xAB],
            };
            let decoded = RelayCell::decode(&cell.encode().unwrap()).unwrap();
            assert_eq!(decoded.stream_id, sid);
        }
    }

    #[test]
    fn test_inner_relay_cell_all_commands_roundtrip() {
        for &cmd in &[
            RelayCommand::Begin,
            RelayCommand::Data,
            RelayCommand::End,
            RelayCommand::Connected,
            RelayCommand::BeginFailed,
        ] {
            let cell = RelayCell {
                command: cmd,
                stream_id: 100,
                data: b"inner-payload".to_vec(),
            };
            let encoded = cell.encode_inner().unwrap();
            let decoded = RelayCell::decode_inner(&encoded).unwrap();
            assert_eq!(decoded.command, cmd);
            assert_eq!(decoded.stream_id, 100);
            assert_eq!(decoded.data, b"inner-payload");
        }
    }

    #[test]
    fn test_inner_data_len_overflow_rejected() {
        let mut buf = [0u8; RELAY_INNER_PLAINTEXT_LEN];
        buf[0] = RelayCommand::Data as u8;
        let bad_len = (RELAY_INNER_MAX_DATA + 100) as u16;
        buf[3..5].copy_from_slice(&bad_len.to_be_bytes());
        assert!(RelayCell::decode_inner(&buf).is_err());
    }
}
