//! Wire-format cell encoding and decoding.
//!
//! All cells are fixed 512 bytes to resist traffic-size analysis.
//! Layout:
//!   [0..4]   circuit_id  (u32, big-endian)
//!   [4]      cell_type   (u8)
//!   [5..512] payload     (507 bytes, zero-padded)

use crate::TransportError;

/// Fixed cell size in bytes.
pub const CELL_SIZE: usize = 512;
/// Payload bytes per cell.
pub const CELL_PAYLOAD_LEN: usize = 507;

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
    /// Encrypted relay data (inner RELAY cell)
    Relay = 3,
    /// Tear down a circuit
    Destroy = 4,
    /// IP/version information exchange (first cell after TCP connect)
    Netinfo = 5,
}

impl CellType {
    /// Parse a byte into a CellType.
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Padding),
            1 => Some(Self::Create),
            2 => Some(Self::Created),
            3 => Some(Self::Relay),
            4 => Some(Self::Destroy),
            5 => Some(Self::Netinfo),
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
        let cell_type = CellType::from_u8(buf[4])
            .ok_or_else(|| TransportError::Protocol(format!("unknown cell type 0x{:02x}", buf[4])))?;
        let mut payload = [0u8; CELL_PAYLOAD_LEN];
        payload.copy_from_slice(&buf[5..CELL_SIZE]);
        Ok(Self { circuit_id, cell_type, payload })
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

/// Commands carried inside an encrypted RELAY cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    /// Ask relay to connect to a target host:port
    Begin = 1,
    /// Forward raw data on a stream
    Data = 2,
    /// Close a stream
    End = 3,
    /// Relay successfully connected to the target
    Connected = 4,
    /// Relay failed to connect
    BeginFailed = 5,
}

impl RelayCommand {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Begin),
            2 => Some(Self::Data),
            3 => Some(Self::End),
            4 => Some(Self::Connected),
            5 => Some(Self::BeginFailed),
            _ => None,
        }
    }
}

/// Maximum data bytes in a relay inner cell (leaves room for header + ChaCha20 tag).
/// 507 payload - 16 (ChaCha20Poly1305 tag) - 5 (inner header) = 486 bytes max data.
pub const RELAY_MAX_DATA: usize = 486;
/// Inner relay cell header size: cmd(1) + stream_id(2) + data_len(2) = 5 bytes.
pub const RELAY_HEADER_LEN: usize = 5;
/// Encrypted relay payload size (inner plaintext before encryption).
pub const RELAY_PLAINTEXT_LEN: usize = CELL_PAYLOAD_LEN - 16; // subtract Poly1305 tag

/// Decoded inner relay cell (parsed from an encrypted RELAY cell's payload).
#[derive(Debug, Clone)]
pub struct RelayCell {
    pub command: RelayCommand,
    pub stream_id: u16,
    pub data: Vec<u8>,
}

impl RelayCell {
    /// Encode into a 491-byte plaintext buffer (to be encrypted into a RELAY cell payload).
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
        let len = self.data.len() as u16;
        buf[3..5].copy_from_slice(&len.to_be_bytes());
        buf[5..5 + self.data.len()].copy_from_slice(&self.data);
        // remaining bytes stay zero (padding)
        Ok(buf)
    }

    /// Decode from a 491-byte decrypted buffer.
    pub fn decode(buf: &[u8; RELAY_PLAINTEXT_LEN]) -> Result<Self, TransportError> {
        let command = RelayCommand::from_u8(buf[0])
            .ok_or_else(|| TransportError::Protocol(format!("unknown relay command 0x{:02x}", buf[0])))?;
        let stream_id = u16::from_be_bytes([buf[1], buf[2]]);
        let data_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        if data_len > RELAY_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "relay inner data_len {} exceeds maximum {}",
                data_len, RELAY_MAX_DATA
            )));
        }
        let data = buf[5..5 + data_len].to_vec();
        Ok(Self { command, stream_id, data })
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
        buf[4] = 0xFF; // unknown type
        let err = Cell::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, TransportError::Protocol(_)));
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
        ] {
            let cell = Cell::new(1, ct);
            let bytes = cell.to_bytes();
            let decoded = Cell::from_bytes(&bytes.try_into().unwrap()).unwrap();
            assert_eq!(decoded.cell_type as u8, ct as u8);
        }
    }

    #[test]
    fn test_cell_size_is_512() {
        let cell = Cell::new(1, CellType::Padding);
        assert_eq!(cell.to_bytes().len(), 512);
    }

    #[test]
    fn test_relay_cell_roundtrip() {
        let inner = RelayCell {
            command: RelayCommand::Data,
            stream_id: 7,
            data: b"hello world".to_vec(),
        };
        let encoded = inner.encode().unwrap();
        let decoded = RelayCell::decode(&encoded).unwrap();
        assert_eq!(decoded.stream_id, 7);
        assert!(matches!(decoded.command, RelayCommand::Data));
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
        let encoded = inner.encode().unwrap();
        let decoded = RelayCell::decode(&encoded).unwrap();
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
        // data_len = RELAY_MAX_DATA + 100 — too large
        let bad_len = (RELAY_MAX_DATA + 100) as u16;
        buf[3..5].copy_from_slice(&bad_len.to_be_bytes());
        assert!(RelayCell::decode(&buf).is_err());
    }
}
