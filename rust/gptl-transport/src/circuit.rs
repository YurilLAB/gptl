//! Circuit abstraction: a single end-to-end anonymized stream path.
//!
//! Phase 1 implements single-hop (client → relay → destination).
//! Multi-hop layered encryption is Phase 2.
//!
//! A `Circuit` wraps a `RelayConn`, holds `CircuitCiphers` for the session,
//! and provides `open_stream` to request a TCP connection through the relay.

use crate::{
    cell::{Cell, CellType, RelayCell, RelayCommand, CELL_PAYLOAD_LEN},
    crypto::CircuitCiphers,
    handshake::SessionKeys,
    relay_conn::RelayConn,
    TransportError,
};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// A unique stream ID within a circuit.
pub type StreamId = u16;

/// Messages sent from the Circuit's reader task to per-stream receivers.
#[derive(Debug)]
pub(crate) enum StreamMessage {
    Data(Vec<u8>),
    End,
    Connected,
    Failed(String),
}

/// A bidirectional stream through the circuit.
///
/// Implements basic read/write: send data with `write`, receive with `read_data`.
pub struct CircuitStream {
    pub stream_id: StreamId,
    pub circuit_id: u32,
    /// Sender for outbound relay cells (shared with the circuit write task)
    pub(crate) outbound_tx: mpsc::Sender<RelayCell>,
    /// Receiver for inbound data/events
    pub(crate) inbound_rx: mpsc::Receiver<StreamMessage>,
}

impl CircuitStream {
    /// Send raw bytes through the stream (splits into multiple RELAY_DATA cells if needed).
    pub async fn write(&self, mut data: &[u8]) -> Result<(), TransportError> {
        use crate::cell::RELAY_MAX_DATA;
        while !data.is_empty() {
            let chunk_len = data.len().min(RELAY_MAX_DATA);
            let chunk = data[..chunk_len].to_vec();
            data = &data[chunk_len..];
            self.outbound_tx
                .send(RelayCell {
                    command: RelayCommand::Data,
                    stream_id: self.stream_id,
                    data: chunk,
                })
                .await
                .map_err(|_| TransportError::CircuitClosed)?;
        }
        Ok(())
    }

    /// Receive incoming data. Returns `None` when the stream is closed.
    pub async fn read_data(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.inbound_rx.recv().await? {
                StreamMessage::Data(d) => return Some(d),
                StreamMessage::End      => return None,
                StreamMessage::Connected | StreamMessage::Failed(_) => continue,
            }
        }
    }

    /// Wait for the relay to confirm it has connected to the destination.
    pub async fn wait_connected(&mut self) -> Result<(), TransportError> {
        loop {
            match self.inbound_rx.recv().await {
                Some(StreamMessage::Connected) => return Ok(()),
                Some(StreamMessage::Failed(reason)) => {
                    return Err(TransportError::Protocol(format!("relay refused: {}", reason)))
                }
                Some(StreamMessage::Data(_)) => continue, // shouldn't happen before CONNECTED
                Some(StreamMessage::End) | None => {
                    return Err(TransportError::Protocol("circuit closed before CONNECTED".into()))
                }
            }
        }
    }

    /// Send a RELAY_END to close this stream.
    pub async fn close(&self) -> Result<(), TransportError> {
        let _ = self.outbound_tx
            .send(RelayCell {
                command: RelayCommand::End,
                stream_id: self.stream_id,
                data: vec![],
            })
            .await;
        Ok(())
    }
}

/// An established circuit to a relay.
///
/// Created by performing the handshake (see `handshake::client_initiate` +
/// `handshake::client_finish`) and calling `Circuit::new`.
pub struct Circuit {
    pub circuit_id: u32,
    ciphers: CircuitCiphers,
    conn: RelayConn,
    streams: HashMap<StreamId, mpsc::Sender<StreamMessage>>,
    next_stream_id: StreamId,
    /// Outbound relay cells queued by `CircuitStream::write`
    outbound_rx: mpsc::Receiver<RelayCell>,
    outbound_tx: mpsc::Sender<RelayCell>,
}

impl Circuit {
    /// Create a circuit from a completed handshake.
    pub fn new(circuit_id: u32, keys: SessionKeys, conn: RelayConn) -> Self {
        let ciphers = CircuitCiphers::new(&keys.forward_key, &keys.backward_key);
        let (tx, rx) = mpsc::channel(64);
        Self {
            circuit_id,
            ciphers,
            conn,
            streams: HashMap::new(),
            next_stream_id: 1,
            outbound_rx: rx,
            outbound_tx: tx,
        }
    }

    /// Request a new TCP stream to `host:port` through the relay.
    ///
    /// Sends a RELAY_BEGIN cell and returns a `CircuitStream`.
    /// Call `stream.wait_connected()` before sending data.
    pub async fn open_stream(
        &mut self,
        host: &str,
        port: u16,
    ) -> Result<CircuitStream, TransportError> {
        let stream_id = self.alloc_stream_id()?;
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        self.streams.insert(stream_id, inbound_tx);

        // Send RELAY_BEGIN with "host:port\0"
        let target = format!("{}:{}", host, port);
        let begin = RelayCell {
            command: RelayCommand::Begin,
            stream_id,
            data: target.into_bytes(),
        };
        self.send_relay_cell(&begin).await?;

        Ok(CircuitStream {
            stream_id,
            circuit_id: self.circuit_id,
            outbound_tx: self.outbound_tx.clone(),
            inbound_rx,
        })
    }

    /// Drive the circuit: flush outbound queued cells and read one inbound cell.
    ///
    /// Call this in a loop.  Returns `Err(TransportError::CircuitClosed)` when
    /// the circuit should be torn down.
    pub async fn step(&mut self) -> Result<(), TransportError> {
        tokio::select! {
            // Flush any queued outbound relay cells
            Some(relay_cell) = self.outbound_rx.recv() => {
                self.send_relay_cell(&relay_cell).await?;
            }
            // Read an inbound cell from the relay
            cell = self.conn.recv() => {
                let cell = cell?;
                self.handle_inbound_cell(cell).await?;
            }
        }
        Ok(())
    }

    /// Tear down the circuit by sending a DESTROY cell.
    pub async fn destroy(&mut self) {
        let cell = Cell::new(self.circuit_id, CellType::Destroy);
        let _ = self.conn.send(&cell).await;
        self.conn.shutdown().await;
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    async fn send_relay_cell(&mut self, inner: &RelayCell) -> Result<(), TransportError> {
        let plaintext = inner.encode()?;
        let ciphertext = self.ciphers.outbound.encrypt(&plaintext)?;
        let mut cell = Cell::new(self.circuit_id, CellType::Relay);
        cell.payload.copy_from_slice(&ciphertext);
        self.conn.send(&cell).await
    }

    async fn handle_inbound_cell(&mut self, cell: Cell) -> Result<(), TransportError> {
        match cell.cell_type {
            CellType::Relay => {
                let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                let pt = self.ciphers.inbound.decrypt(&ct)?;
                let inner = RelayCell::decode(&pt)?;
                self.dispatch_relay_cell(inner).await;
            }
            CellType::Destroy => {
                return Err(TransportError::CircuitClosed);
            }
            CellType::Padding => {} // ignore
            _ => {
                tracing::warn!(
                    "unexpected cell type {:?} on established circuit {}",
                    cell.cell_type,
                    self.circuit_id
                );
            }
        }
        Ok(())
    }

    async fn dispatch_relay_cell(&mut self, inner: RelayCell) {
        let stream_id = inner.stream_id;
        let tx = match self.streams.get(&stream_id) {
            Some(tx) => tx.clone(), // clone to release the immutable borrow before any mutation
            None => return,
        };

        let msg = match inner.command {
            RelayCommand::Data      => StreamMessage::Data(inner.data),
            RelayCommand::End       => {
                self.streams.remove(&stream_id);
                StreamMessage::End
            }
            RelayCommand::Connected   => StreamMessage::Connected,
            RelayCommand::BeginFailed => {
                let reason = String::from_utf8_lossy(&inner.data).to_string();
                StreamMessage::Failed(reason)
            }
            _ => return,
        };
        let _ = tx.send(msg).await;
    }

    fn alloc_stream_id(&mut self) -> Result<StreamId, TransportError> {
        // Stream IDs are odd on the client side (Tor convention).
        // Wrap at u16::MAX - 1.
        let id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(2);
        if self.next_stream_id == 0 {
            self.next_stream_id = 1; // skip 0
        }
        if self.streams.len() >= 1000 {
            return Err(TransportError::Protocol("too many open streams on circuit".into()));
        }
        Ok(id)
    }
}
