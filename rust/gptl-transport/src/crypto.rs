//! Per-circuit ChaCha20Poly1305 cell encryption / decryption.
//!
//! Each circuit direction has its own key and a monotonically increasing nonce
//! counter.  The 12-byte nonce is `counter (u64 big-endian) ++ 0x00_00_00_00`.
//!
//! A RELAY cell payload is 507 bytes.  After encryption the ciphertext (including
//! the 16-byte Poly1305 tag) occupies exactly 507 bytes:
//!   plaintext 491 bytes + tag 16 bytes = 507 bytes.

use crate::cell::{CELL_PAYLOAD_LEN, RELAY_PLAINTEXT_LEN};
use crate::TransportError;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

/// Direction-specific cipher and counter for encrypting/decrypting relay cells.
pub struct CellCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl CellCipher {
    /// Create from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            counter: 0,
        }
    }

    /// Encrypt a 491-byte plaintext into a 507-byte payload (in-place + appended tag).
    ///
    /// The returned array is exactly `CELL_PAYLOAD_LEN` (507) bytes.
    pub fn encrypt(&mut self, plaintext: &[u8; RELAY_PLAINTEXT_LEN]) -> Result<[u8; CELL_PAYLOAD_LEN], TransportError> {
        let nonce = self.next_nonce()?;
        let mut buf = plaintext.to_vec();
        self.cipher
            .encrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|e| TransportError::Crypto(format!("encryption failed: {}", e)))?;
        // buf is now 491 + 16 = 507 bytes
        let mut out = [0u8; CELL_PAYLOAD_LEN];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// Decrypt a 507-byte cell payload into a 491-byte plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8; CELL_PAYLOAD_LEN]) -> Result<[u8; RELAY_PLAINTEXT_LEN], TransportError> {
        let nonce = self.next_nonce()?;
        let mut buf = ciphertext.to_vec();
        self.cipher
            .decrypt_in_place(&nonce, b"", &mut buf)
            .map_err(|_| TransportError::Crypto("decryption failed — authentication tag mismatch".into()))?;
        // buf is now 507 - 16 = 491 bytes
        let mut out = [0u8; RELAY_PLAINTEXT_LEN];
        out.copy_from_slice(&buf);
        Ok(out)
    }

    /// Current send/receive counter (exposed for tests).
    pub fn counter(&self) -> u64 {
        self.counter
    }

    fn next_nonce(&mut self) -> Result<Nonce, TransportError> {
        let c = self.counter;
        self.counter = self.counter.checked_add(1)
            .ok_or_else(|| TransportError::Crypto("nonce counter exhausted (2^64 cells)".into()))?;
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&c.to_be_bytes());
        Ok(*Nonce::from_slice(&nonce))
    }
}

/// A pair of ciphers: one per direction.
pub struct CircuitCiphers {
    /// Encrypt cells going client→relay
    pub outbound: CellCipher,
    /// Decrypt cells coming relay→client
    pub inbound: CellCipher,
}

impl CircuitCiphers {
    pub fn new(forward_key: &[u8; 32], backward_key: &[u8; 32]) -> Self {
        Self {
            outbound: CellCipher::new(forward_key),
            inbound: CellCipher::new(backward_key),
        }
    }
}

/// Relay-side cipher pair (mirror of client-side).
pub struct RelayCiphers {
    /// Decrypt cells coming from the client (was forward on client side)
    pub inbound: CellCipher,
    /// Encrypt cells going to the client (was backward on client side)
    pub outbound: CellCipher,
}

impl RelayCiphers {
    pub fn new(forward_key: &[u8; 32], backward_key: &[u8; 32]) -> Self {
        Self {
            inbound: CellCipher::new(forward_key),
            outbound: CellCipher::new(backward_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        k
    }

    fn random_plaintext() -> [u8; RELAY_PLAINTEXT_LEN] {
        let mut p = [0u8; RELAY_PLAINTEXT_LEN];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut p);
        p
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let mut dec = CellCipher::new(&key);
        let plaintext = random_plaintext();

        let ciphertext = enc.encrypt(&plaintext).unwrap();
        let recovered = dec.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, recovered);
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let plaintext = [0x42u8; RELAY_PLAINTEXT_LEN];
        let ciphertext = enc.encrypt(&plaintext).unwrap();
        // Encrypted output must not equal input
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = random_key();
        let key2 = random_key();
        let mut enc1 = CellCipher::new(&key1);
        let mut enc2 = CellCipher::new(&key2);
        let plaintext = random_plaintext();
        let ct1 = enc1.encrypt(&plaintext).unwrap();
        let ct2 = enc2.encrypt(&plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let mut enc = CellCipher::new(&key1);
        let mut dec = CellCipher::new(&key2);
        let plaintext = random_plaintext();
        let ciphertext = enc.encrypt(&plaintext).unwrap();
        assert!(dec.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let mut dec = CellCipher::new(&key);
        let plaintext = random_plaintext();
        let mut ciphertext = enc.encrypt(&plaintext).unwrap();
        // Flip a bit in the ciphertext body
        ciphertext[10] ^= 0x01;
        assert!(dec.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_tampered_auth_tag_rejected() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let mut dec = CellCipher::new(&key);
        let plaintext = random_plaintext();
        let mut ciphertext = enc.encrypt(&plaintext).unwrap();
        // Corrupt the Poly1305 tag (last 16 bytes)
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert!(dec.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_counter_increments_each_call() {
        let key = random_key();
        let mut cipher = CellCipher::new(&key);
        assert_eq!(cipher.counter(), 0);
        let pt = [0u8; RELAY_PLAINTEXT_LEN];
        let _ = cipher.encrypt(&pt).unwrap();
        assert_eq!(cipher.counter(), 1);
        let _ = cipher.encrypt(&pt).unwrap();
        assert_eq!(cipher.counter(), 2);
    }

    #[test]
    fn test_replay_attack_fails_due_to_nonce_mismatch() {
        // If attacker replays ciphertext #0 as ciphertext #1,
        // the decoder at counter=1 must reject it.
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let mut dec = CellCipher::new(&key);
        let plaintext = random_plaintext();

        let ct0 = enc.encrypt(&plaintext).unwrap();
        // decoder consumes counter=0 successfully
        let _ = dec.decrypt(&ct0).unwrap();
        // now replay ct0 again — decoder is at counter=1 and will reject
        assert!(dec.decrypt(&ct0).is_err());
    }

    #[test]
    fn test_same_plaintext_different_counters_produce_different_ciphertexts() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let plaintext = random_plaintext();
        let ct0 = enc.encrypt(&plaintext).unwrap();
        let ct1 = enc.encrypt(&plaintext).unwrap();
        // Nonce changes each call — ciphertext must differ
        assert_ne!(ct0, ct1);
    }

    #[test]
    fn test_multiple_roundtrips() {
        let key = random_key();
        let mut enc = CellCipher::new(&key);
        let mut dec = CellCipher::new(&key);
        for i in 0..20 {
            let mut pt = [0u8; RELAY_PLAINTEXT_LEN];
            pt[0] = i;
            let ct = enc.encrypt(&pt).unwrap();
            let recovered = dec.decrypt(&ct).unwrap();
            assert_eq!(pt, recovered, "roundtrip failed at iteration {}", i);
        }
    }
}
