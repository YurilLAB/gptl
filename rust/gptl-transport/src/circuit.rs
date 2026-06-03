//! Circuit abstraction: a multi-hop end-to-end anonymized stream path.
//!
//! Phase 1 implements single-hop (client → relay → destination).
//! Phase 2 adds multi-hop layered encryption via `Circuit::extend`.
//!
//! A `Circuit` wraps a `RelayConn`, holds one `CircuitCiphers` per hop,
//! and provides `open_stream` to request a TCP connection through the circuit.

use crate::{
    bootstrap::RelayDescriptor,
    cell::{
        Cell, CellType, RelayCell, RelayCommand, CELL_PAYLOAD_LEN, RELAY_INNER_CT_LEN,
        RELAY_MAX_DATA,
    },
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
        // Use RELAY_INNER_MAX_DATA as the conservative limit so cells fit in
        // 2-hop mode too.  Single-hop mode wastes ~21 bytes but stays correct.
        use crate::cell::RELAY_INNER_MAX_DATA;
        let max_chunk = RELAY_INNER_MAX_DATA;
        while !data.is_empty() {
            let chunk_len = data.len().min(max_chunk);
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
                StreamMessage::End => return None,
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
                    return Err(TransportError::Protocol(format!(
                        "relay refused: {}",
                        reason
                    )))
                }
                Some(StreamMessage::Data(_)) => continue, // shouldn't happen before CONNECTED
                Some(StreamMessage::End) | None => {
                    return Err(TransportError::Protocol(
                        "circuit closed before CONNECTED".into(),
                    ))
                }
            }
        }
    }

    /// Send a RELAY_END to close this stream.
    pub async fn close(&self) -> Result<(), TransportError> {
        let _ = self
            .outbound_tx
            .send(RelayCell {
                command: RelayCommand::End,
                stream_id: self.stream_id,
                data: vec![],
            })
            .await;
        Ok(())
    }
}

/// An established circuit to one or more relays.
///
/// Created by performing the handshake (see `handshake::client_initiate` +
/// `handshake::client_finish`) and calling `Circuit::new`.
///
/// For multi-hop circuits, call `Circuit::extend` after construction.
pub struct Circuit {
    pub circuit_id: u32,
    /// Ordered hop ciphers: index 0 = hop1 (closest relay), index N-1 = exit relay.
    hops: Vec<CircuitCiphers>,
    conn: RelayConn,
    streams: HashMap<StreamId, mpsc::Sender<StreamMessage>>,
    next_stream_id: StreamId,
    /// Outbound relay cells queued by `CircuitStream::write`
    outbound_rx: mpsc::Receiver<RelayCell>,
    outbound_tx: mpsc::Sender<RelayCell>,
    /// Wire-level PADDING cell trigger.  Sending `()` here causes
    /// `step()` to emit a `CellType::Padding` cell with a random payload
    /// directly on the underlying connection — bypassing the relay
    /// encryption layer (padding is consumed by the first hop and never
    /// reaches any stream).
    padding_rx: mpsc::Receiver<()>,
    padding_tx: mpsc::Sender<()>,
    /// Oneshot sender for routing RELAY_EXTENDED/ExtendFailed back to extend().
    /// Present only while extend() is in progress.
    pending_extend_tx: Option<tokio::sync::oneshot::Sender<Result<RelayCell, TransportError>>>,
}

impl Circuit {
    /// Create a circuit from a completed handshake.
    pub fn new(circuit_id: u32, keys: SessionKeys, conn: RelayConn) -> Self {
        let ciphers = CircuitCiphers::new(&keys.forward_key, &keys.backward_key);
        let (tx, rx) = mpsc::channel(64);
        let (ptx, prx) = mpsc::channel(16);
        Self {
            circuit_id,
            hops: vec![ciphers],
            conn,
            streams: HashMap::new(),
            next_stream_id: 1,
            outbound_rx: rx,
            outbound_tx: tx,
            padding_rx: prx,
            padding_tx: ptx,
            pending_extend_tx: None,
        }
    }

    /// Sender side of the wire-level PADDING-cell trigger channel.
    /// `splice()` clones this to inject cover traffic.
    pub fn padding_trigger(&self) -> mpsc::Sender<()> {
        self.padding_tx.clone()
    }

    /// Returns the number of hops in this circuit.
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Extend the circuit by one more hop through `relay`.
    ///
    /// Generates a fresh X25519 ephemeral keypair, sends RELAY_EXTEND to the
    /// current exit relay, waits for RELAY_EXTENDED, verifies the key
    /// confirmation, and pushes new `CircuitCiphers` for the new hop.
    pub async fn extend(&mut self, relay: &RelayDescriptor) -> Result<(), TransportError> {
        if self.hops.len() >= 2 {
            return Err(TransportError::Protocol(
                "extend beyond 2 hops not yet supported".into(),
            ));
        }

        let relay2_pubkey = relay.pubkey_bytes()?;

        // ── Generate key material via the authenticated handshake ────────────
        // Build the inner CREATE using the same two-DH (ntor-style) primitive
        // as a direct connection. The CREATE cell's first 96 payload bytes carry
        // [relay2_fingerprint || client_ephemeral_pub || client_nonce]; we tunnel
        // exactly those bytes inside RELAY_EXTEND so relay1 can forward them.
        let (create_cell, pending) =
            crate::handshake::client_initiate(self.circuit_id, &relay2_pubkey)?;
        let handshake_material = &create_cell.payload[0..96];

        // ── Build RELAY_EXTEND payload ───────────────────────────────────────
        // [0..4]            addr_len (u32 BE)
        // [4..4+addr_len]   "ip:port"
        // [off..off+96]     CREATE handshake material (fp || eph_pub || nonce)
        let addr_bytes = relay.address.as_bytes();
        let addr_len = addr_bytes.len() as u32;

        let payload_len = 4 + addr_bytes.len() + 96;
        if payload_len > RELAY_MAX_DATA {
            return Err(TransportError::Protocol(format!(
                "RELAY_EXTEND payload too large: {} bytes (max {})",
                payload_len, RELAY_MAX_DATA
            )));
        }

        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&addr_len.to_be_bytes());
        payload.extend_from_slice(addr_bytes);
        payload.extend_from_slice(handshake_material);

        let extend_cell = RelayCell {
            command: RelayCommand::Extend,
            stream_id: 0,
            data: payload,
        };

        // ── Register a oneshot for the response ─────────────────────────────
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_extend_tx = Some(tx);

        // ── Send RELAY_EXTEND through the current (1-hop) circuit ───────────
        self.send_relay_cell_raw(&extend_cell).await?;

        // ── Pump until we get RELAY_EXTENDED or ExtendFailed ────────────────
        let extended_cell = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.recv_until_extend_response(rx),
        )
        .await
        .map_err(|_| TransportError::Protocol("RELAY_EXTEND timed out after 30s".into()))??;

        // ── Complete the key derivation ──────────────────────────────────────
        // RELAY_EXTENDED carries the CREATED handshake response in its first 96
        // bytes: [relay2_ephemeral_pub || relay2_nonce || key_confirmation].
        // Reconstruct a CREATED cell and run the same authenticated two-DH
        // finish, which derives the keys AND verifies the confirmation
        // (constant-time), authenticating relay2 via its static key.
        if extended_cell.data.len() < 96 {
            return Err(TransportError::Handshake(format!(
                "RELAY_EXTENDED payload too short: {} bytes (need 96)",
                extended_cell.data.len()
            )));
        }

        let mut created = Cell::new(self.circuit_id, CellType::Created);
        created.payload[0..96].copy_from_slice(&extended_cell.data[0..96]);

        let keys = crate::handshake::client_finish(pending, &created)?;

        // ── Add new hop ──────────────────────────────────────────────────────
        self.hops
            .push(CircuitCiphers::new(&keys.forward_key, &keys.backward_key));
        Ok(())
    }

    /// Request a new TCP stream to `host:port` through the circuit.
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

        // Send RELAY_BEGIN with "host:port"
        let target = format!("{}:{}", host, port);
        let begin = RelayCell {
            command: RelayCommand::Begin,
            stream_id,
            data: target.into_bytes(),
        };
        self.send_relay_cell_raw(&begin).await?;

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
                self.send_relay_cell_raw(&relay_cell).await?;
            }
            // Wire-level PADDING cell with a random payload — first hop drops it.
            Some(()) = self.padding_rx.recv() => {
                let pad = Cell::padding(self.circuit_id);
                self.conn.send(&pad).await?;
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

    /// Encrypt and send a relay cell through all current hops.
    ///
    /// - 1 hop: encode() + encrypt(hops[0].outbound) → RELAY cell
    /// - 2 hops: encode_inner() + encrypt_inner(hops[1].outbound)
    ///   → wrap in Forward{stream_id=0, data=CT}
    ///   → encode() + encrypt(hops[0].outbound) → RELAY cell
    async fn send_relay_cell_raw(&mut self, inner: &RelayCell) -> Result<(), TransportError> {
        match self.hops.len() {
            0 => Err(TransportError::Protocol("circuit has no hops".into())),
            1 => {
                let plaintext = inner.encode()?;
                let ciphertext = self.hops[0].outbound.encrypt(&plaintext)?;
                let mut cell = Cell::new(self.circuit_id, CellType::Relay);
                cell.payload.copy_from_slice(&ciphertext);
                self.conn.send(&cell).await
            }
            2 => {
                // Encrypt inner layer (hop1→relay2)
                let inner_pt = inner.encode_inner()?;
                let inner_ct = self.hops[1].outbound.encrypt_inner(&inner_pt)?;

                // Wrap in RELAY_FORWARD for outer layer
                let forward = RelayCell {
                    command: RelayCommand::Forward,
                    stream_id: 0,
                    data: inner_ct.to_vec(),
                };
                let outer_pt = forward.encode()?;
                let outer_ct = self.hops[0].outbound.encrypt(&outer_pt)?;
                let mut cell = Cell::new(self.circuit_id, CellType::Relay);
                cell.payload.copy_from_slice(&outer_ct);
                self.conn.send(&cell).await
            }
            n => Err(TransportError::Protocol(format!(
                "send_relay_cell_raw: {} hops not supported (max 2)",
                n
            ))),
        }
    }

    /// Decrypt an inbound cell down to the innermost `RelayCell`.
    ///
    /// For 1-hop: decrypt(hops[0].inbound) + decode()
    /// For 2-hop: decrypt(hops[0].inbound) + decode() → expect Forward
    ///             → decrypt_inner(hops[1].inbound) + decode_inner()
    ///
    /// Circuit-level cells that arrive on the outer layer in 2-hop mode
    /// (e.g. RELAY_EXTENDED, RELAY_EXTEND_FAILED) are passed through as-is.
    fn decrypt_to_inner(&mut self, cell: Cell) -> Result<DecryptResult, TransportError> {
        match cell.cell_type {
            CellType::Relay => {}
            CellType::Destroy => return Ok(DecryptResult::Destroy),
            CellType::Padding => return Ok(DecryptResult::Padding),
            other => {
                tracing::warn!(
                    "unexpected cell type {:?} on circuit {}",
                    other,
                    self.circuit_id
                );
                return Ok(DecryptResult::Padding);
            }
        }

        let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
        let pt = self.hops[0].inbound.decrypt(&ct)?;
        let outer = RelayCell::decode(&pt)?;

        if self.hops.len() == 1 {
            return Ok(DecryptResult::Cell(outer));
        }

        // 2-hop: outer layer must be Forward (or a circuit-level message)
        match outer.command {
            RelayCommand::Forward => {
                // Inner ciphertext is in outer.data (486 bytes)
                let inner_ct_slice = &outer.data;
                if inner_ct_slice.len() != RELAY_INNER_CT_LEN {
                    return Err(TransportError::Protocol(format!(
                        "RELAY_FORWARD inner ciphertext wrong size: {} (expected {})",
                        inner_ct_slice.len(),
                        RELAY_INNER_CT_LEN
                    )));
                }
                let inner_ct: [u8; RELAY_INNER_CT_LEN] =
                    inner_ct_slice.as_slice().try_into().map_err(|_| {
                        TransportError::Protocol("inner CT slice conversion failed".into())
                    })?;
                let inner_pt = self.hops[1].inbound.decrypt_inner(&inner_ct)?;
                let inner_cell = RelayCell::decode_inner(&inner_pt)?;
                Ok(DecryptResult::Cell(inner_cell))
            }
            // Circuit-level commands (Extended, ExtendFailed) arrive on the outer layer
            // even in 2-hop mode — pass them through directly
            RelayCommand::Extended | RelayCommand::ExtendFailed => Ok(DecryptResult::Cell(outer)),
            other => {
                tracing::warn!(
                    "circuit {} 2-hop: unexpected outer command {:?} (expected Forward or circuit-level)",
                    self.circuit_id,
                    other
                );
                Ok(DecryptResult::Padding)
            }
        }
    }

    async fn handle_inbound_cell(&mut self, cell: Cell) -> Result<(), TransportError> {
        match self.decrypt_to_inner(cell)? {
            DecryptResult::Cell(inner) => {
                self.dispatch_relay_cell(inner).await;
            }
            DecryptResult::Destroy => {
                return Err(TransportError::CircuitClosed);
            }
            DecryptResult::Padding => {}
        }
        Ok(())
    }

    async fn dispatch_relay_cell(&mut self, inner: RelayCell) {
        match inner.command {
            RelayCommand::Extended | RelayCommand::ExtendFailed => {
                // Route to pending_extend_tx if one is registered
                if let Some(tx) = self.pending_extend_tx.take() {
                    let result = if inner.command == RelayCommand::ExtendFailed {
                        let reason = String::from_utf8_lossy(&inner.data).into_owned();
                        Err(TransportError::Handshake(format!(
                            "extend failed: {}",
                            reason
                        )))
                    } else {
                        Ok(inner)
                    };
                    // Ignore send errors — extend() may have timed out
                    let _ = tx.send(result);
                } else {
                    tracing::warn!(
                        "circuit {} received {:?} but no extend in progress",
                        self.circuit_id,
                        inner.command
                    );
                }
            }
            RelayCommand::Data
            | RelayCommand::End
            | RelayCommand::Connected
            | RelayCommand::BeginFailed => {
                let stream_id = inner.stream_id;
                let tx =
                    match self.streams.get(&stream_id) {
                        Some(tx) => tx.clone(),
                        None => {
                            tracing::debug!(
                            "circuit {} stream {} not found (may be already closed), dropping {:?}",
                            self.circuit_id, stream_id, inner.command
                        );
                            return;
                        }
                    };

                let msg = match inner.command {
                    RelayCommand::Data => StreamMessage::Data(inner.data),
                    RelayCommand::End => {
                        self.streams.remove(&stream_id);
                        StreamMessage::End
                    }
                    RelayCommand::Connected => StreamMessage::Connected,
                    RelayCommand::BeginFailed => {
                        let reason = String::from_utf8_lossy(&inner.data).to_string();
                        StreamMessage::Failed(reason)
                    }
                    _ => unreachable!(),
                };
                let _ = tx.send(msg).await;
            }
            other => {
                tracing::warn!(
                    "circuit {} unhandled relay command {:?} on stream {}",
                    self.circuit_id,
                    other,
                    inner.stream_id
                );
            }
        }
    }

    /// Pump the circuit until we receive RELAY_EXTENDED or RELAY_EXTEND_FAILED.
    ///
    /// This is called internally by `extend()` while `pending_extend_tx` is set.
    async fn recv_until_extend_response(
        &mut self,
        rx: tokio::sync::oneshot::Receiver<Result<RelayCell, TransportError>>,
    ) -> Result<RelayCell, TransportError> {
        // Use a fused receiver so we can poll it in select!
        let mut rx = rx;
        loop {
            tokio::select! {
                // Flush queued outbound stream cells
                Some(relay_cell) = self.outbound_rx.recv() => {
                    self.send_relay_cell_raw(&relay_cell).await?;
                }
                // Inbound cell from relay1
                result = self.conn.recv() => {
                    let cell = result?;
                    self.handle_inbound_cell(cell).await?;
                }
                // The oneshot fires when dispatch_relay_cell routes Extended/ExtendFailed
                result = &mut rx => {
                    return result.map_err(|_| TransportError::Protocol(
                        "extend oneshot dropped unexpectedly".into(),
                    ))?;
                }
            }
        }
    }

    /// Allocate the next odd stream ID, skipping IDs already in use.
    fn alloc_stream_id(&mut self) -> Result<StreamId, TransportError> {
        // Stream IDs are odd on the client side (Tor convention).
        // Max 32767 odd values in [1, 65535].
        if self.streams.len() >= 32767 {
            return Err(TransportError::Protocol(
                "all stream IDs exhausted on circuit".into(),
            ));
        }

        // Walk through odd IDs until we find one that is not currently open.
        let start = self.next_stream_id;
        loop {
            let id = self.next_stream_id;
            // Advance (wrapping, odd only)
            self.next_stream_id = self.next_stream_id.checked_add(2).unwrap_or(1);
            if self.next_stream_id == 0 {
                self.next_stream_id = 1;
            }

            if !self.streams.contains_key(&id) {
                return Ok(id);
            }

            // If we've cycled all the way around without finding a free ID
            // (shouldn't happen given the len check above, but be safe)
            if self.next_stream_id == start {
                return Err(TransportError::Protocol("stream ID space exhausted".into()));
            }
        }
    }
}

/// Internal result of `decrypt_to_inner`.
enum DecryptResult {
    Cell(RelayCell),
    Destroy,
    Padding,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bootstrap::RelayDescriptor,
        cell::{Cell, CellType, CELL_PAYLOAD_LEN, RELAY_PLAINTEXT_LEN},
        crypto::RelayCiphers,
        handshake::{client_finish, client_initiate, relay_respond, RelayStaticKey},
        relay_conn::RelayConn,
    };
    use tokio::net::TcpListener;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Perform a complete in-process handshake and return a connected (Circuit, RelayConn).
    async fn make_circuit_and_relay() -> (Circuit, RelayConn) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let relay_key = RelayStaticKey::generate();

        let (circuit, relay_conn) = tokio::join!(
            async {
                let relay_conn = RelayConn::connect(addr).await.unwrap();
                let circuit_id = 1u32;
                let (create, pending) = client_initiate(circuit_id, &relay_key.public).unwrap();
                let mut rc = relay_conn;
                // rc is consumed by Circuit::new, so we do the handshake manually
                let _ = rc.send(&create).await;
                let created = rc.recv().await.unwrap();
                let keys = client_finish(pending, &created).unwrap();
                Circuit::new(circuit_id, keys, rc)
            },
            async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut rc = RelayConn::new(stream);
                let create = rc.recv().await.unwrap();
                let (created, _keys) = relay_respond(&create, &relay_key).unwrap();
                rc.send(&created).await.unwrap();
                rc
            }
        );
        (circuit, relay_conn)
    }

    // ── alloc_stream_id ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_alloc_stream_id_returns_odd_ids() {
        let (mut circuit, _) = make_circuit_and_relay().await;
        let id1 = circuit.alloc_stream_id().unwrap();
        let id2 = circuit.alloc_stream_id().unwrap();
        assert_eq!(id1 % 2, 1, "stream IDs must be odd");
        assert_eq!(id2 % 2, 1, "stream IDs must be odd");
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_alloc_stream_id_skips_in_use() {
        let (mut circuit, _) = make_circuit_and_relay().await;
        // Manually insert stream_id=1 as occupied
        let (tx, _rx) = mpsc::channel(1);
        circuit.streams.insert(1, tx);
        // next alloc should skip 1 and return 3
        let id = circuit.alloc_stream_id().unwrap();
        assert_eq!(id, 3);
    }

    // ── send/recv single-hop ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_send_relay_cell_raw_1hop_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_key = RelayStaticKey::generate();

        // Setup relay side
        let relay_task = tokio::spawn({
            let relay_key = relay_key.clone();
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut rc = RelayConn::new(stream);
                let create = rc.recv().await.unwrap();
                let (created, keys) = relay_respond(&create, &relay_key).unwrap();
                rc.send(&created).await.unwrap();
                // Receive one relay cell and decrypt it
                let cell = rc.recv().await.unwrap();
                let mut relay_ciphers = RelayCiphers::new(&keys.forward_key, &keys.backward_key);
                let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                let pt = relay_ciphers.inbound.decrypt(&ct).unwrap();
                crate::cell::RelayCell::decode(&pt).unwrap()
            }
        });

        let mut relay_conn = RelayConn::connect(addr).await.unwrap();
        let circuit_id = 1u32;
        let (create, pending) = client_initiate(circuit_id, &relay_key.public).unwrap();
        relay_conn.send(&create).await.unwrap();
        let created = relay_conn.recv().await.unwrap();
        let keys = client_finish(pending, &created).unwrap();
        let mut circuit = Circuit::new(circuit_id, keys, relay_conn);

        let cell = RelayCell {
            command: RelayCommand::Data,
            stream_id: 7,
            data: b"hello single-hop".to_vec(),
        };
        circuit.send_relay_cell_raw(&cell).await.unwrap();

        let received = relay_task.await.unwrap();
        assert_eq!(received.stream_id, 7);
        assert_eq!(received.data, b"hello single-hop");
    }

    // ── 2-hop extend ─────────────────────────────────────────────────────────

    /// Full extend() test with an in-process relay1 and relay2.
    #[tokio::test]
    async fn test_extend_two_hop_completes() {
        // ── Setup relay2 ─────────────────────────────────────────────────────
        let relay2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay2_addr = relay2_listener.local_addr().unwrap();
        let relay2_key = RelayStaticKey::generate();

        let relay2_task = tokio::spawn({
            let relay2_key = relay2_key.clone();
            async move {
                let (stream, _) = relay2_listener.accept().await.unwrap();
                let _ = stream.set_nodelay(true);
                let mut conn = RelayConn::new(stream);
                let create = conn.recv().await.unwrap();
                let (created, _keys) = relay_respond(&create, &relay2_key).unwrap();
                conn.send(&created).await.unwrap();
                // Done — relay2 stays up for the duration
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        // ── Setup relay1 ─────────────────────────────────────────────────────
        let relay1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay1_addr = relay1_listener.local_addr().unwrap();
        let relay1_key = RelayStaticKey::generate();

        let relay2_addr_str = relay2_addr.to_string();
        let relay1_task = tokio::spawn({
            let relay1_key = relay1_key.clone();
            async move {
                let (stream, _) = relay1_listener.accept().await.unwrap();
                let _ = stream.set_nodelay(true);
                let mut rc = RelayConn::new(stream);

                // Handshake
                let create = rc.recv().await.unwrap();
                let (created, keys) = relay_respond(&create, &relay1_key).unwrap();
                rc.send(&created).await.unwrap();

                let mut ciphers = RelayCiphers::new(&keys.forward_key, &keys.backward_key);

                // Receive RELAY_EXTEND
                let cell = rc.recv().await.unwrap();
                let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                let pt = ciphers.inbound.decrypt(&ct).unwrap();
                let extend_cell = crate::cell::RelayCell::decode(&pt).unwrap();
                assert_eq!(extend_cell.command, RelayCommand::Extend);

                // Parse
                let data = &extend_cell.data;
                let addr_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let off = 4 + addr_len;
                let fp: [u8; 32] = data[off..off + 32].try_into().unwrap();
                let client_eph: [u8; 32] = data[off + 32..off + 64].try_into().unwrap();
                let client_nonce2: [u8; 32] = data[off + 64..off + 96].try_into().unwrap();

                // Connect to relay2
                let mut relay2_rc = RelayConn::connect(relay2_addr).await.unwrap();

                // Proxy CREATE → relay2
                let mut create2 = Cell::new(create.circuit_id, CellType::Create);
                create2.payload[0..32].copy_from_slice(&fp);
                create2.payload[32..64].copy_from_slice(&client_eph);
                create2.payload[64..96].copy_from_slice(&client_nonce2);
                relay2_rc.send(&create2).await.unwrap();

                // Receive CREATED from relay2
                let created2 = relay2_rc.recv().await.unwrap();
                assert!(matches!(created2.cell_type, CellType::Created));

                // Send RELAY_EXTENDED to client
                let extended = crate::cell::RelayCell {
                    command: RelayCommand::Extended,
                    stream_id: 0,
                    data: created2.payload[0..96].to_vec(),
                };
                let pt2: [u8; RELAY_PLAINTEXT_LEN] = extended.encode().unwrap();
                let ct2 = ciphers.outbound.encrypt(&pt2).unwrap();
                let mut resp = Cell::new(create.circuit_id, CellType::Relay);
                resp.payload.copy_from_slice(&ct2);
                rc.send(&resp).await.unwrap();

                // Keep relay1 alive briefly
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        // ── Client: connect to relay1 and extend ─────────────────────────────
        let mut relay1_rc = RelayConn::connect(relay1_addr).await.unwrap();
        let circuit_id = 1u32;
        let (create, pending) = client_initiate(circuit_id, &relay1_key.public).unwrap();
        relay1_rc.send(&create).await.unwrap();
        let created = relay1_rc.recv().await.unwrap();
        let keys = client_finish(pending, &created).unwrap();
        let mut circuit = Circuit::new(circuit_id, keys, relay1_rc);

        assert_eq!(circuit.hop_count(), 1);

        let relay2_desc = RelayDescriptor {
            nickname: "relay2".into(),
            address: relay2_addr_str,
            pubkey_hex: hex::encode(relay2_key.public),
        };

        circuit.extend(&relay2_desc).await.unwrap();
        assert_eq!(circuit.hop_count(), 2);

        relay1_task.await.unwrap();
        relay2_task.await.unwrap();
    }

    /// extend() with bad key confirmation must fail.
    #[tokio::test]
    async fn test_extend_bad_confirmation_rejected() {
        let relay2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay2_addr = relay2_listener.local_addr().unwrap();
        let relay2_key = RelayStaticKey::generate();

        // relay2: accept handshake but corrupt the confirmation in Created
        let relay2_task = tokio::spawn({
            let relay2_key = relay2_key.clone();
            async move {
                let (stream, _) = relay2_listener.accept().await.unwrap();
                let mut conn = RelayConn::new(stream);
                let create = conn.recv().await.unwrap();
                let (mut created, _keys) = relay_respond(&create, &relay2_key).unwrap();
                // Corrupt confirmation
                created.payload[64] ^= 0xFF;
                conn.send(&created).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        // relay1: proxy CREATE/CREATED without modification
        let relay1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay1_addr = relay1_listener.local_addr().unwrap();
        let relay1_key = RelayStaticKey::generate();

        let relay1_task = tokio::spawn({
            let relay1_key = relay1_key.clone();
            async move {
                let (stream, _) = relay1_listener.accept().await.unwrap();
                let _ = stream.set_nodelay(true);
                let mut rc = RelayConn::new(stream);

                let create = rc.recv().await.unwrap();
                let (created, keys) = relay_respond(&create, &relay1_key).unwrap();
                rc.send(&created).await.unwrap();
                let mut ciphers = RelayCiphers::new(&keys.forward_key, &keys.backward_key);

                let cell = rc.recv().await.unwrap();
                let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                let pt = ciphers.inbound.decrypt(&ct).unwrap();
                let extend_cell = crate::cell::RelayCell::decode(&pt).unwrap();

                let data = &extend_cell.data;
                let addr_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let off = 4 + addr_len;
                let fp: [u8; 32] = data[off..off + 32].try_into().unwrap();
                let client_eph: [u8; 32] = data[off + 32..off + 64].try_into().unwrap();
                let client_nc: [u8; 32] = data[off + 64..off + 96].try_into().unwrap();

                let mut r2rc = RelayConn::connect(relay2_addr).await.unwrap();
                let mut c2 = Cell::new(create.circuit_id, CellType::Create);
                c2.payload[0..32].copy_from_slice(&fp);
                c2.payload[32..64].copy_from_slice(&client_eph);
                c2.payload[64..96].copy_from_slice(&client_nc);
                r2rc.send(&c2).await.unwrap();

                let created2 = r2rc.recv().await.unwrap();
                let extended = crate::cell::RelayCell {
                    command: RelayCommand::Extended,
                    stream_id: 0,
                    data: created2.payload[0..96].to_vec(),
                };
                let pt2: [u8; RELAY_PLAINTEXT_LEN] = extended.encode().unwrap();
                let ct2 = ciphers.outbound.encrypt(&pt2).unwrap();
                let mut resp = Cell::new(create.circuit_id, CellType::Relay);
                resp.payload.copy_from_slice(&ct2);
                rc.send(&resp).await.unwrap();

                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        let mut relay1_rc = RelayConn::connect(relay1_addr).await.unwrap();
        let circuit_id = 2u32;
        let (create, pending) = client_initiate(circuit_id, &relay1_key.public).unwrap();
        relay1_rc.send(&create).await.unwrap();
        let created = relay1_rc.recv().await.unwrap();
        let keys = client_finish(pending, &created).unwrap();
        let mut circuit = Circuit::new(circuit_id, keys, relay1_rc);

        let relay2_desc = RelayDescriptor {
            nickname: "relay2-bad".into(),
            address: relay2_addr.to_string(),
            pubkey_hex: hex::encode(relay2_key.public),
        };

        let result = circuit.extend(&relay2_desc).await;
        assert!(result.is_err(), "extend with bad confirmation must fail");
        assert!(
            matches!(result.unwrap_err(), TransportError::Handshake(_)),
            "error must be Handshake"
        );

        relay1_task.await.unwrap();
        relay2_task.await.unwrap();
    }

    // ── extend limit ─────────────────────────────────────────────────────────

    /// extend() on a 2-hop circuit must return an error immediately.
    #[tokio::test]
    async fn test_extend_limit_enforced() {
        // We need a 2-hop circuit; use the same approach as test_extend_two_hop_completes
        // but then call extend a third time and verify failure.
        let relay2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay2_addr = relay2_listener.local_addr().unwrap();
        let relay2_key = RelayStaticKey::generate();

        let relay2_task = tokio::spawn({
            let relay2_key = relay2_key.clone();
            async move {
                let (stream, _) = relay2_listener.accept().await.unwrap();
                let mut conn = RelayConn::new(stream);
                let create = conn.recv().await.unwrap();
                let (created, _keys) = relay_respond(&create, &relay2_key).unwrap();
                conn.send(&created).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        });

        let relay1_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay1_addr = relay1_listener.local_addr().unwrap();
        let relay1_key = RelayStaticKey::generate();
        let relay2_addr_str = relay2_addr.to_string();

        let relay1_task = tokio::spawn({
            let relay1_key = relay1_key.clone();
            async move {
                let (stream, _) = relay1_listener.accept().await.unwrap();
                let _ = stream.set_nodelay(true);
                let mut rc = RelayConn::new(stream);
                let create = rc.recv().await.unwrap();
                let (created, keys) = relay_respond(&create, &relay1_key).unwrap();
                rc.send(&created).await.unwrap();
                let mut ciphers =
                    crate::crypto::RelayCiphers::new(&keys.forward_key, &keys.backward_key);

                let cell = rc.recv().await.unwrap();
                let ct: [u8; CELL_PAYLOAD_LEN] = cell.payload;
                let pt = ciphers.inbound.decrypt(&ct).unwrap();
                let extend_cell = crate::cell::RelayCell::decode(&pt).unwrap();
                let data = &extend_cell.data;
                let addr_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let off = 4 + addr_len;
                let fp: [u8; 32] = data[off..off + 32].try_into().unwrap();
                let client_eph: [u8; 32] = data[off + 32..off + 64].try_into().unwrap();
                let client_nonce2: [u8; 32] = data[off + 64..off + 96].try_into().unwrap();

                let mut relay2_rc = RelayConn::connect(relay2_addr).await.unwrap();
                let mut create2 = Cell::new(create.circuit_id, CellType::Create);
                create2.payload[0..32].copy_from_slice(&fp);
                create2.payload[32..64].copy_from_slice(&client_eph);
                create2.payload[64..96].copy_from_slice(&client_nonce2);
                relay2_rc.send(&create2).await.unwrap();
                let created2 = relay2_rc.recv().await.unwrap();

                let extended = crate::cell::RelayCell {
                    command: RelayCommand::Extended,
                    stream_id: 0,
                    data: created2.payload[0..96].to_vec(),
                };
                let pt2: [u8; crate::cell::RELAY_PLAINTEXT_LEN] = extended.encode().unwrap();
                let ct2 = ciphers.outbound.encrypt(&pt2).unwrap();
                let mut resp = Cell::new(create.circuit_id, CellType::Relay);
                resp.payload.copy_from_slice(&ct2);
                rc.send(&resp).await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            }
        });

        let mut relay1_rc = RelayConn::connect(relay1_addr).await.unwrap();
        let circuit_id = 1u32;
        let (create, pending) = client_initiate(circuit_id, &relay1_key.public).unwrap();
        relay1_rc.send(&create).await.unwrap();
        let created = relay1_rc.recv().await.unwrap();
        let keys = client_finish(pending, &created).unwrap();
        let mut circuit = Circuit::new(circuit_id, keys, relay1_rc);

        // Extend to 2 hops
        let relay2_desc = RelayDescriptor {
            nickname: "relay2".into(),
            address: relay2_addr_str,
            pubkey_hex: hex::encode(relay2_key.public),
        };
        circuit.extend(&relay2_desc).await.unwrap();
        assert_eq!(circuit.hop_count(), 2);

        // Attempt a third extend — must fail immediately
        let dummy_desc = RelayDescriptor {
            nickname: "relay3".into(),
            address: "127.0.0.1:9999".into(),
            pubkey_hex: hex::encode([0u8; 32]),
        };
        let result = circuit.extend(&dummy_desc).await;
        assert!(result.is_err(), "extend beyond 2 hops must return an error");
        assert!(
            matches!(result.unwrap_err(), TransportError::Protocol(_)),
            "error must be Protocol type"
        );

        relay1_task.await.unwrap();
        relay2_task.await.unwrap();
    }

    // ── stream close sends RELAY_END ────────────────────────────────────────

    /// open_stream + close must enqueue a RELAY_END cell in outbound_tx.
    #[tokio::test]
    async fn test_stream_close_sends_end() {
        let (mut circuit, _relay_conn) = make_circuit_and_relay().await;
        // Get a handle to the outbound channel before opening a stream
        let outbound_tx = circuit.outbound_tx.clone();

        // Open a stream (sends RELAY_BEGIN via send_relay_cell_raw, which goes direct
        // in 1-hop; the `outbound_tx` is for queued outbound from CircuitStream)
        let stream = circuit.open_stream("example.com", 80).await.unwrap();
        let sid = stream.stream_id;

        // Close the stream — this sends RELAY_END into outbound_tx
        stream.close().await.unwrap();

        // The RELAY_END must now be in the channel
        let mut rx = {
            let (_, rx) = (outbound_tx, circuit.outbound_rx);
            rx
        };
        let cell = rx
            .recv()
            .await
            .expect("expected RELAY_END in outbound channel");
        assert_eq!(
            cell.command,
            RelayCommand::End,
            "close() must send RELAY_END"
        );
        assert_eq!(
            cell.stream_id, sid,
            "RELAY_END must carry the correct stream_id"
        );
    }

    // ── hop_count ─────────────────────────────────────────────────────────────

    /// hop_count() == 1 after new(), == 2 after one successful extend().
    #[tokio::test]
    async fn test_circuit_hop_count() {
        let (circuit, _) = make_circuit_and_relay().await;
        assert_eq!(circuit.hop_count(), 1, "new circuit must have 1 hop");
        // A 2-hop extend is already covered in test_extend_two_hop_completes;
        // this test just verifies the baseline count.
        drop(circuit);
    }

    #[tokio::test]
    async fn test_destroy_sends_destroy_cell() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_key = RelayStaticKey::generate();

        let relay_task = tokio::spawn({
            let relay_key = relay_key.clone();
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut rc = RelayConn::new(stream);
                let create = rc.recv().await.unwrap();
                let (created, _) = relay_respond(&create, &relay_key).unwrap();
                rc.send(&created).await.unwrap();
                let cell = rc.recv().await.unwrap();
                cell.cell_type
            }
        });

        let mut relay_conn = RelayConn::connect(addr).await.unwrap();
        let (create, pending) = client_initiate(1, &relay_key.public).unwrap();
        relay_conn.send(&create).await.unwrap();
        let created = relay_conn.recv().await.unwrap();
        let keys = client_finish(pending, &created).unwrap();
        let mut circuit = Circuit::new(1, keys, relay_conn);

        circuit.destroy().await;

        let cell_type = relay_task.await.unwrap();
        assert!(matches!(cell_type, CellType::Destroy));
    }
}
