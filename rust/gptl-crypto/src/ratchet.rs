//! Forward Secrecy and Key Ratcheting
//!
//! Implements key rotation and ratcheting mechanisms for forward secrecy.
//! Based on Signal Double Ratchet specification (2025-2026).

use crate::{CellEncryptionError, KeyExchangeError, SharedSecret};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Forward secrecy manager with key ratcheting
///
/// Implements periodic key rotation to provide forward secrecy.
/// Keys are rotated based on time, message count, or data volume.
pub struct ForwardSecrecy {
    /// Key rotation interval
    rotation_interval: Duration,
    /// Last rotation time
    last_rotation: Instant,
    /// Message counter
    message_count: u64,
    /// Maximum messages before rotation
    max_messages: u64,
    /// Data volume counter (bytes)
    data_volume: u64,
    /// Maximum data volume before rotation (bytes)
    max_data_volume: u64,
}

impl ForwardSecrecy {
    /// Create new forward secrecy manager
    ///
    /// # Arguments
    /// * `rotation_interval` - Time-based rotation interval
    /// * `max_messages` - Maximum messages before rotation (default: 2^20)
    /// * `max_data_volume` - Maximum data volume before rotation (default: 100GB)
    pub fn new(rotation_interval: Duration) -> Self {
        Self {
            rotation_interval,
            last_rotation: Instant::now(),
            message_count: 0,
            max_messages: 1 << 20, // 2^20 messages (NIST recommendation)
            data_volume: 0,
            max_data_volume: 100 * 1024 * 1024 * 1024, // 100GB
        }
    }

    /// Create with custom limits
    pub fn with_limits(
        rotation_interval: Duration,
        max_messages: u64,
        max_data_volume: u64,
    ) -> Self {
        Self {
            rotation_interval,
            last_rotation: Instant::now(),
            message_count: 0,
            max_messages,
            data_volume: 0,
            max_data_volume,
        }
    }

    /// Check if key rotation is needed
    pub fn needs_rotation(&self) -> bool {
        // Time-based rotation
        if self.last_rotation.elapsed() >= self.rotation_interval {
            return true;
        }

        // Message count rotation
        if self.message_count >= self.max_messages {
            return true;
        }

        // Data volume rotation
        if self.data_volume >= self.max_data_volume {
            return true;
        }

        false
    }

    /// Mark rotation as complete
    pub fn mark_rotated(&mut self) {
        self.last_rotation = Instant::now();
        self.message_count = 0;
        self.data_volume = 0;
    }

    /// Record message sent/received
    pub fn record_message(&mut self, data_size: usize) {
        self.message_count += 1;
        self.data_volume += data_size as u64;
    }

    /// Get rotation statistics
    pub fn stats(&self) -> RotationStats {
        RotationStats {
            time_since_rotation: self.last_rotation.elapsed(),
            message_count: self.message_count,
            data_volume: self.data_volume,
            needs_rotation: self.needs_rotation(),
        }
    }
}

/// Rotation statistics
#[derive(Debug, Clone)]
pub struct RotationStats {
    /// Time since last rotation
    pub time_since_rotation: Duration,
    /// Messages since last rotation
    pub message_count: u64,
    /// Data volume since last rotation (bytes)
    pub data_volume: u64,
    /// Whether rotation is needed
    pub needs_rotation: bool,
}

/// Key ratchet for Double Ratchet algorithm
///
/// Simplified implementation of Signal's Double Ratchet.
/// For production, consider using a full Double Ratchet implementation.
pub struct KeyRatchet {
    /// Root key (zeroized)
    root_key: Zeroizing<[u8; 32]>,
    /// Chain key for sending (zeroized)
    send_chain_key: Zeroizing<[u8; 32]>,
    /// Chain key for receiving (zeroized)
    recv_chain_key: Zeroizing<[u8; 32]>,
    /// Send message number
    send_count: u64,
    /// Receive message number
    recv_count: u64,
}

impl KeyRatchet {
    /// Create new key ratchet from a shared secret using HKDF-SHA256.
    ///
    /// `initiator` selects the role: the two peers MUST pass opposite values so
    /// that one peer's *send* chain equals the other peer's *recv* chain. (If
    /// both sides derived the send chain from the same label, both directions
    /// would share a key stream — catastrophic key reuse — and a sender's key
    /// would not match the receiver's.)
    pub fn new(shared_secret: &SharedSecret, initiator: bool) -> Result<Self, KeyExchangeError> {
        if shared_secret.0.len() < 32 {
            return Err(KeyExchangeError::SharedSecretFailed(
                "Shared secret too short".to_string(),
            ));
        }

        // Derive initial root and two *directional* chain keys via HKDF
        // (salt = zero vector for the initial derivation).
        let zeros = [0u8; 32];
        let root_key = Self::hkdf_derive(&shared_secret.0, &zeros, b"gptl-root-key");
        let i2r = Self::hkdf_derive(&shared_secret.0, &root_key, b"gptl-chain-initiator-to-responder");
        let r2i = Self::hkdf_derive(&shared_secret.0, &root_key, b"gptl-chain-responder-to-initiator");

        // Assign send/recv by role so they cross-wire between the two peers.
        let (send_chain_key, recv_chain_key) = if initiator { (i2r, r2i) } else { (r2i, i2r) };

        Ok(Self {
            root_key: Zeroizing::new(root_key),
            send_chain_key: Zeroizing::new(send_chain_key),
            recv_chain_key: Zeroizing::new(recv_chain_key),
            send_count: 0,
            recv_count: 0,
        })
    }

    /// Derive next sending key and advance the send chain.
    pub fn next_send_key(&mut self) -> Result<[u8; 32], CellEncryptionError> {
        // Message key: HKDF(IKM=chain_key, salt=chain_key, info="msg-key")
        let key = Self::hkdf_derive(
            &self.send_chain_key[..],
            &self.send_chain_key[..],
            b"gptl-msg-key",
        );

        // Advance chain key: HKDF(IKM=chain_key, salt=chain_key, info="chain-key")
        *self.send_chain_key = Self::hkdf_derive(
            &self.send_chain_key[..],
            &self.send_chain_key[..],
            b"gptl-chain-key",
        );
        self.send_count += 1;

        Ok(key)
    }

    /// Derive next receiving key and advance the receive chain.
    pub fn next_recv_key(&mut self) -> Result<[u8; 32], CellEncryptionError> {
        let key = Self::hkdf_derive(
            &self.recv_chain_key[..],
            &self.recv_chain_key[..],
            b"gptl-msg-key",
        );

        *self.recv_chain_key = Self::hkdf_derive(
            &self.recv_chain_key[..],
            &self.recv_chain_key[..],
            b"gptl-chain-key",
        );
        self.recv_count += 1;

        Ok(key)
    }

    /// Perform a DH ratchet step (simplified Double Ratchet).
    ///
    /// `sending = true` is the step you take after generating a fresh DH key
    /// pair (updates the root and the *send* chain). `sending = false` is the
    /// step you take on receiving the peer's new DH public key (updates the root
    /// and the *recv* chain). Both peers derive the new chain from the same
    /// `dh_output` and the (equal) current root with the same label, so your
    /// send chain after a send-step equals the peer's recv chain after the
    /// matching recv-step. Steps must alternate (send/recv) to stay in sync.
    pub fn ratchet_dh(
        &mut self,
        dh_output: &SharedSecret,
        sending: bool,
    ) -> Result<(), KeyExchangeError> {
        if dh_output.0.len() < 32 {
            return Err(KeyExchangeError::SharedSecretFailed(
                "DH output too short".to_string(),
            ));
        }

        // KDF_RK: HKDF(salt=root_key, IKM=dh_output) → new root + new chain.
        let new_root_key = Self::hkdf_derive(&dh_output.0, &self.root_key[..], b"ratchet-root-key");
        let new_chain_key =
            Self::hkdf_derive(&dh_output.0, &self.root_key[..], b"ratchet-chain-key");

        *self.root_key = new_root_key;
        if sending {
            *self.send_chain_key = new_chain_key;
            self.send_count = 0;
        } else {
            *self.recv_chain_key = new_chain_key;
            self.recv_count = 0;
        }

        Ok(())
    }

    /// Derive a 32-byte key using HKDF-SHA256.
    ///
    /// `salt` provides domain separation (use the current chain/root key).
    /// `info` provides context binding.
    fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        use aws_lc_rs::hkdf;

        let s = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
        let prk = s.extract(ikm);
        let mut output = [0u8; 32];
        prk.expand(&[info], hkdf::HKDF_SHA256)
            .expect("HKDF expand: valid length")
            .fill(&mut output)
            .expect("HKDF fill: valid length");
        output
    }

    /// Get ratchet statistics
    pub fn stats(&self) -> RatchetStats {
        RatchetStats {
            send_count: self.send_count,
            recv_count: self.recv_count,
        }
    }
}

/// Ratchet statistics
#[derive(Debug, Clone)]
pub struct RatchetStats {
    /// Number of messages sent
    pub send_count: u64,
    /// Number of messages received
    pub recv_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_secrecy_time_rotation() {
        let mut fs = ForwardSecrecy::new(Duration::from_millis(100));
        assert!(!fs.needs_rotation());

        std::thread::sleep(Duration::from_millis(150));
        assert!(fs.needs_rotation());

        fs.mark_rotated();
        assert!(!fs.needs_rotation());
    }

    #[test]
    fn test_forward_secrecy_message_rotation() {
        let mut fs = ForwardSecrecy::with_limits(
            Duration::from_secs(3600),
            10, // Rotate after 10 messages
            1_000_000,
        );

        for _ in 0..9 {
            fs.record_message(100);
            assert!(!fs.needs_rotation());
        }

        fs.record_message(100);
        assert!(fs.needs_rotation());
    }

    #[test]
    fn test_forward_secrecy_data_volume_rotation() {
        let mut fs = ForwardSecrecy::with_limits(
            Duration::from_secs(3600),
            1_000_000,
            1000, // Rotate after 1000 bytes
        );

        fs.record_message(500);
        assert!(!fs.needs_rotation());

        fs.record_message(500);
        assert!(fs.needs_rotation());
    }

    #[test]
    fn test_key_ratchet() {
        let shared_secret = SharedSecret(Zeroizing::new(vec![0u8; 32]));
        let mut ratchet = KeyRatchet::new(&shared_secret, true).unwrap();

        let key1 = ratchet.next_send_key().unwrap();
        let key2 = ratchet.next_send_key().unwrap();

        // Keys should be different
        assert_ne!(key1, key2);

        let stats = ratchet.stats();
        assert_eq!(stats.send_count, 2);
    }

    #[test]
    fn test_key_ratchet_separate_chains() {
        let shared_secret = SharedSecret(Zeroizing::new(vec![0u8; 32]));
        let mut ratchet = KeyRatchet::new(&shared_secret, true).unwrap();

        let send_key = ratchet.next_send_key().unwrap();
        let recv_key = ratchet.next_recv_key().unwrap();

        // Send and receive keys should be different
        assert_ne!(send_key, recv_key);
    }

    #[test]
    fn test_ratchet_forward_secrecy_old_keys_differ_from_new() {
        // After a DH ratchet step the new message keys must differ from
        // the ones produced before the step.
        let shared_secret = SharedSecret(Zeroizing::new(vec![0xABu8; 32]));
        let mut ratchet = KeyRatchet::new(&shared_secret, true).unwrap();

        // Produce a key before the ratchet step
        let old_send_key = ratchet.next_send_key().unwrap();

        // Perform a DH ratchet step with a fresh DH output
        let new_dh_output = SharedSecret(Zeroizing::new(vec![0x99u8; 32]));
        ratchet.ratchet_dh(&new_dh_output, true).unwrap();

        // After the ratchet the next send key must differ from the pre-ratchet key
        let new_send_key = ratchet.next_send_key().unwrap();
        assert_ne!(
            old_send_key, new_send_key,
            "send key after ratchet must differ from pre-ratchet send key"
        );
    }

    #[test]
    fn test_ratchet_after_max_messages_send_count_advances() {
        let shared_secret = SharedSecret(Zeroizing::new(vec![0x01u8; 32]));
        let mut ratchet = KeyRatchet::new(&shared_secret, true).unwrap();

        // Simulate sending max_messages worth of messages (use 100 as a proxy)
        let limit = 100usize;
        let mut keys = Vec::with_capacity(limit);
        for _ in 0..limit {
            keys.push(ratchet.next_send_key().unwrap());
        }

        // All keys should be unique (no repeats before rotation)
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(
            unique.len(),
            limit,
            "every pre-rotation message key must be unique"
        );

        let stats = ratchet.stats();
        assert_eq!(
            stats.send_count, limit as u64,
            "send_count must equal the number of send keys consumed"
        );
    }

    #[test]
    fn test_ratchet_dh_step_resets_relevant_counter() {
        let shared_secret = SharedSecret(Zeroizing::new(vec![0x07u8; 32]));
        let mut ratchet = KeyRatchet::new(&shared_secret, true).unwrap();

        for _ in 0..5 {
            ratchet.next_send_key().unwrap();
        }
        for _ in 0..3 {
            ratchet.next_recv_key().unwrap();
        }
        assert_eq!(ratchet.stats().send_count, 5);
        assert_eq!(ratchet.stats().recv_count, 3);

        // A *sending* DH step resets only the send counter.
        let dh = SharedSecret(Zeroizing::new(vec![0x77u8; 32]));
        ratchet.ratchet_dh(&dh, true).unwrap();
        assert_eq!(ratchet.stats().send_count, 0, "send_count resets on a send-step");
        assert_eq!(ratchet.stats().recv_count, 3, "recv_count unchanged by a send-step");

        // A *receiving* DH step resets only the recv counter.
        let dh2 = SharedSecret(Zeroizing::new(vec![0x88u8; 32]));
        ratchet.ratchet_dh(&dh2, false).unwrap();
        assert_eq!(ratchet.stats().recv_count, 0, "recv_count resets on a recv-step");
    }

    #[test]
    fn test_ratchet_two_parties_chains_cross_wire() {
        // The initiator's SEND chain must equal the responder's RECV chain (and
        // vice versa), so a message encrypted by one decrypts on the other, and
        // the two directions use INDEPENDENT key streams. (Regression: the old
        // code derived both peers' send chains from the same label, making both
        // directions share a key stream — catastrophic key reuse.)
        let secret = SharedSecret(Zeroizing::new(vec![0x42u8; 32]));
        let mut initiator = KeyRatchet::new(&secret, true).unwrap();
        let mut responder = KeyRatchet::new(&secret, false).unwrap();

        // initiator -> responder
        let i_send1 = initiator.next_send_key().unwrap();
        let r_recv1 = responder.next_recv_key().unwrap();
        assert_eq!(i_send1, r_recv1, "initiator send[0] must equal responder recv[0]");
        let i_send2 = initiator.next_send_key().unwrap();
        let r_recv2 = responder.next_recv_key().unwrap();
        assert_eq!(i_send2, r_recv2, "initiator send[1] must equal responder recv[1]");

        // responder -> initiator
        let r_send1 = responder.next_send_key().unwrap();
        let i_recv1 = initiator.next_recv_key().unwrap();
        assert_eq!(r_send1, i_recv1, "responder send[0] must equal initiator recv[0]");

        // The two directions must NOT share a key stream.
        assert_ne!(i_send1, r_send1, "the two directions must use independent keys");
    }

    #[test]
    fn test_dh_ratchet_send_step_matches_peer_recv_step() {
        // After a DH step, the initiator's new send chain must equal the
        // responder's new recv chain (both derive from the same dh_output).
        let secret = SharedSecret(Zeroizing::new(vec![0x11u8; 32]));
        let mut initiator = KeyRatchet::new(&secret, true).unwrap();
        let mut responder = KeyRatchet::new(&secret, false).unwrap();

        let dh = SharedSecret(Zeroizing::new(vec![0x55u8; 32]));
        initiator.ratchet_dh(&dh, true).unwrap(); // initiator generated a new DH key
        responder.ratchet_dh(&dh, false).unwrap(); // responder received it

        let i_send = initiator.next_send_key().unwrap();
        let r_recv = responder.next_recv_key().unwrap();
        assert_eq!(i_send, r_recv, "post-DH send chain must match peer's recv chain");
    }

    #[test]
    fn test_ratchet_short_shared_secret_rejected() {
        let short = SharedSecret(Zeroizing::new(vec![0u8; 16]));
        let result = KeyRatchet::new(&short, true);
        assert!(
            result.is_err(),
            "shared secret shorter than 32 bytes must be rejected"
        );
    }

    #[test]
    fn test_forward_secrecy_mark_rotated_resets_all_counters() {
        let mut fs = ForwardSecrecy::with_limits(Duration::from_secs(3600), 5, 1000);

        for _ in 0..5 {
            fs.record_message(100);
        }
        assert!(
            fs.needs_rotation(),
            "should need rotation after max_messages reached"
        );

        fs.mark_rotated();
        assert!(
            !fs.needs_rotation(),
            "should not need rotation immediately after mark_rotated"
        );

        let stats = fs.stats();
        assert_eq!(
            stats.message_count, 0,
            "message_count must reset after rotation"
        );
        assert_eq!(
            stats.data_volume, 0,
            "data_volume must reset after rotation"
        );
    }
}
