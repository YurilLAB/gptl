//! Framed TCP connection that reads and writes fixed-size 512-byte cells.

use crate::cell::{Cell, CELL_SIZE};
use crate::TransportError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::net::SocketAddr;

/// A TCP connection that speaks the GPTL cell protocol.
///
/// All reads and writes are in terms of fixed 512-byte cells.
pub struct RelayConn {
    stream: TcpStream,
}

impl RelayConn {
    /// Wrap an already-established TCP stream.
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// Connect to a relay at `addr` and return a wrapped connection.
    pub async fn connect(addr: SocketAddr) -> Result<Self, TransportError> {
        let stream = TcpStream::connect(addr).await
            .map_err(|e| TransportError::Io(format!("connect to {}: {}", addr, e)))?;
        // Disable Nagle — we always send full 512-byte cells.
        let _ = stream.set_nodelay(true);
        Ok(Self::new(stream))
    }

    /// Send one cell.
    pub async fn send(&mut self, cell: &Cell) -> Result<(), TransportError> {
        let bytes = cell.to_bytes();
        self.stream.write_all(&bytes).await
            .map_err(|e| TransportError::Io(format!("write cell: {}", e)))
    }

    /// Receive one cell (blocks until exactly 512 bytes arrive).
    pub async fn recv(&mut self) -> Result<Cell, TransportError> {
        let mut buf = [0u8; CELL_SIZE];
        self.stream.read_exact(&mut buf).await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    TransportError::ConnectionClosed
                } else {
                    TransportError::Io(format!("read cell: {}", e))
                }
            })?;
        Cell::from_bytes(&buf)
    }

    /// Gracefully shut down the write half.
    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// Return the peer's remote address, if available.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.stream.peer_addr().ok()
    }

    /// Unwrap into the underlying `TcpStream` (e.g. to call `into_split`).
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::CellType;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_send_recv_cell_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = RelayConn::new(stream);
            conn.recv().await.unwrap()
        });

        let mut client = RelayConn::connect(addr).await.unwrap();
        let mut cell = Cell::new(99, CellType::Create);
        cell.payload[0] = 0xBE;
        cell.payload[506] = 0xEF;
        client.send(&cell).await.unwrap();

        let received = server.await.unwrap();
        assert_eq!(received.circuit_id, 99);
        assert!(matches!(received.cell_type, CellType::Create));
        assert_eq!(received.payload[0], 0xBE);
        assert_eq!(received.payload[506], 0xEF);
    }

    #[tokio::test]
    async fn test_multiple_cells_in_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = RelayConn::new(stream);
            let c1 = conn.recv().await.unwrap();
            let c2 = conn.recv().await.unwrap();
            (c1, c2)
        });

        let mut client = RelayConn::connect(addr).await.unwrap();
        let cell1 = Cell::new(1, CellType::Padding);
        let cell2 = Cell::new(2, CellType::Destroy);
        client.send(&cell1).await.unwrap();
        client.send(&cell2).await.unwrap();

        let (r1, r2) = server.await.unwrap();
        assert_eq!(r1.circuit_id, 1);
        assert_eq!(r2.circuit_id, 2);
    }

    #[tokio::test]
    async fn test_connection_closed_returns_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept then immediately close
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream);
        });

        let mut client = RelayConn::connect(addr).await.unwrap();
        let result = client.recv().await;
        assert!(matches!(result, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn test_peer_addr_is_set() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let conn = RelayConn::connect(addr).await.unwrap();
        assert!(conn.peer_addr().is_some());
    }
}
