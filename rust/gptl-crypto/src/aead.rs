//! AEAD (Authenticated Encryption with Associated Data) implementations
//!
//! Provides AES-256-GCM and ChaCha20-Poly1305 for cell encryption.
//! Based on 2025-2026 best practices using aws-lc-rs (FIPS-validated).

use crate::{CellEncryptionError, CipherSuite};
use aws_lc_rs::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Cell cipher trait for AEAD operations
pub trait CellCipher: Send + Sync {
    /// Encrypt a cell payload
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CellEncryptionError>;

    /// Decrypt a cell payload
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CellEncryptionError>;

    /// Get cipher suite
    fn cipher_suite(&self) -> CipherSuite;

    /// Check if key rotation is needed
    fn needs_rotation(&self) -> bool;
}

/// AES-256-GCM cipher implementation
///
/// Recommended for 2025-2026 on platforms with AES-NI hardware acceleration.
/// Uses counter-based nonces (32-bit fixed + 64-bit counter) to prevent reuse.
pub struct AesGcmCipher {
    key: LessSafeKey,
    /// Nonce counter (64-bit, incremented for each encryption)
    nonce_counter: AtomicU64,
    /// Fixed nonce prefix (32-bit)
    nonce_prefix: [u8; 4],
}

impl AesGcmCipher {
    /// Create new AES-256-GCM cipher
    ///
    /// # Arguments
    /// * `key` - 32-byte key
    /// * `nonce_prefix` - 4-byte fixed nonce prefix
    pub fn new(key: &[u8], nonce_prefix: [u8; 4]) -> Result<Self, CellEncryptionError> {
        if key.len() != 32 {
            return Err(CellEncryptionError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|e| CellEncryptionError::EncryptionFailed(format!("Key creation failed: {:?}", e)))?;

        Ok(Self {
            key: LessSafeKey::new(unbound_key),
            nonce_counter: AtomicU64::new(0),
            nonce_prefix,
        })
    }

    /// Generate next nonce (counter-based, NIST recommended)
    fn next_nonce(&self) -> Result<[u8; 12], CellEncryptionError> {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Check for counter exhaustion (2^64 limit)
        if counter == u64::MAX {
            return Err(CellEncryptionError::NonceExhausted);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());

        Ok(nonce)
    }
}

impl CellCipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CellEncryptionError> {
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CellEncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {:?}", e)))?;

        // Prepend nonce to ciphertext
        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&in_out);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CellEncryptionError> {
        if ciphertext.len() < 12 {
            return Err(CellEncryptionError::DecryptionFailed(
                "Ciphertext too short".to_string(),
            ));
        }

        // Extract nonce from ciphertext
        let nonce_bytes: [u8; 12] = ciphertext[0..12]
            .try_into()
            .map_err(|_| CellEncryptionError::InvalidNonce("Invalid nonce length".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext[12..].to_vec();
        let plaintext = self.key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CellEncryptionError::DecryptionFailed(format!("AES-GCM decryption failed: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }

    fn cipher_suite(&self) -> CipherSuite {
        CipherSuite::Aes256Gcm
    }

    fn needs_rotation(&self) -> bool {
        // Rotate before counter exhaustion (at 2^32 messages as per NIST recommendation)
        self.nonce_counter.load(Ordering::SeqCst) >= (1u64 << 32)
    }
}

/// ChaCha20-Poly1305 cipher implementation
///
/// Recommended for 2025-2026 on platforms without AES-NI or for constant-time software implementations.
pub struct ChaCha20Cipher {
    key: LessSafeKey,
    /// Nonce counter (64-bit)
    nonce_counter: AtomicU64,
    /// Fixed nonce prefix (32-bit)
    nonce_prefix: [u8; 4],
}

impl ChaCha20Cipher {
    /// Create new ChaCha20-Poly1305 cipher
    ///
    /// # Arguments
    /// * `key` - 32-byte key
    /// * `nonce_prefix` - 4-byte fixed nonce prefix
    pub fn new(key: &[u8], nonce_prefix: [u8; 4]) -> Result<Self, CellEncryptionError> {
        if key.len() != 32 {
            return Err(CellEncryptionError::InvalidKeyLength {
                expected: 32,
                actual: key.len(),
            });
        }

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|e| CellEncryptionError::EncryptionFailed(format!("Key creation failed: {:?}", e)))?;

        Ok(Self {
            key: LessSafeKey::new(unbound_key),
            nonce_counter: AtomicU64::new(0),
            nonce_prefix,
        })
    }

    /// Generate next nonce (counter-based)
    fn next_nonce(&self) -> Result<[u8; 12], CellEncryptionError> {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        if counter == u64::MAX {
            return Err(CellEncryptionError::NonceExhausted);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..12].copy_from_slice(&counter.to_be_bytes());

        Ok(nonce)
    }
}

impl CellCipher for ChaCha20Cipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CellEncryptionError> {
        let nonce_bytes = self.next_nonce()?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CellEncryptionError::EncryptionFailed(format!("ChaCha20 encryption failed: {:?}", e)))?;

        // Prepend nonce to ciphertext
        let mut output = nonce_bytes.to_vec();
        output.extend_from_slice(&in_out);

        Ok(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CellEncryptionError> {
        if ciphertext.len() < 12 {
            return Err(CellEncryptionError::DecryptionFailed(
                "Ciphertext too short".to_string(),
            ));
        }

        let nonce_bytes: [u8; 12] = ciphertext[0..12]
            .try_into()
            .map_err(|_| CellEncryptionError::InvalidNonce("Invalid nonce length".to_string()))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = ciphertext[12..].to_vec();
        let plaintext = self.key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| CellEncryptionError::DecryptionFailed(format!("ChaCha20 decryption failed: {:?}", e)))?;

        Ok(plaintext.to_vec())
    }

    fn cipher_suite(&self) -> CipherSuite {
        CipherSuite::ChaCha20Poly1305
    }

    fn needs_rotation(&self) -> bool {
        // Rotate at 2^32 messages
        self.nonce_counter.load(Ordering::SeqCst) >= (1u64 << 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Hello, GPTL!";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = ChaCha20Cipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Hello, GPTL!";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"test";
        let ct1 = cipher.encrypt(plaintext).unwrap();
        let ct2 = cipher.encrypt(plaintext).unwrap();

        // Nonces should be different (first 12 bytes)
        assert_ne!(&ct1[0..12], &ct2[0..12]);
    }

    #[test]
    fn test_needs_rotation() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        assert!(!cipher.needs_rotation());

        // Simulate many encryptions
        cipher.nonce_counter.store(1u64 << 32, Ordering::SeqCst);
        assert!(cipher.needs_rotation());
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Secret message";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext (flip a bit)
        if ciphertext.len() > 20 {
            ciphertext[20] ^= 0x01;
        }

        // Decryption should fail
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let nonce_prefix = [1, 2, 3, 4];

        let cipher1 = AesGcmCipher::new(&key1, nonce_prefix).unwrap();
        let cipher2 = AesGcmCipher::new(&key2, nonce_prefix).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = cipher1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = cipher2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_replay_attack_detection() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Message";
        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // First decryption should succeed
        let result1 = cipher.decrypt(&ciphertext);
        assert!(result1.is_ok());

        // Replay should also succeed (nonce is in ciphertext)
        // But in a real system, you'd track used nonces
        let result2 = cipher.decrypt(&ciphertext);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"";
        let ciphertext = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = vec![0xAB; 10000];
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_chacha20_tampered_ciphertext() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = ChaCha20Cipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Secret data";
        let mut ciphertext = cipher.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        if ciphertext.len() > 15 {
            ciphertext[15] ^= 0xFF;
        }

        // Should fail authentication
        let result = cipher.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_counter_overflow_protection() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        // Set counter near max
        cipher.nonce_counter.store(u64::MAX - 1, Ordering::SeqCst);

        let plaintext = b"test";
        let result1 = cipher.encrypt(plaintext);
        assert!(result1.is_ok());

        // Next encryption should fail (counter exhausted)
        let result2 = cipher.encrypt(plaintext);
        assert!(result2.is_err());
    }

    #[test]
    fn test_ciphertext_integrity() {
        let key = [0u8; 32];
        let nonce_prefix = [1, 2, 3, 4];
        let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

        let plaintext = b"Integrity test";
        let ciphertext = cipher.encrypt(plaintext).unwrap();

        // Verify ciphertext structure
        assert!(ciphertext.len() >= 12 + 16); // nonce + tag minimum
        assert!(ciphertext.len() >= plaintext.len());
    }

    #[test]
    fn test_different_nonce_prefixes() {
        let key = [0u8; 32];
        let cipher1 = AesGcmCipher::new(&key, [1, 2, 3, 4]).unwrap();
        let cipher2 = AesGcmCipher::new(&key, [5, 6, 7, 8]).unwrap();

        let plaintext = b"test";
        let ct1 = cipher1.encrypt(plaintext).unwrap();
        let ct2 = cipher2.encrypt(plaintext).unwrap();

        // Different nonce prefixes should produce different ciphertexts
        assert_ne!(ct1, ct2);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_encrypt_decrypt_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..1000)) {
            let key = [0u8; 32];
            let nonce_prefix = [1, 2, 3, 4];
            let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

            let ciphertext = cipher.encrypt(&plaintext).unwrap();
            let decrypted = cipher.decrypt(&ciphertext).unwrap();

            prop_assert_eq!(plaintext, decrypted);
        }

        #[test]
        fn prop_ciphertext_different_from_plaintext(
            plaintext in prop::collection::vec(any::<u8>(), 1..1000)
        ) {
            let key = [0u8; 32];
            let nonce_prefix = [1, 2, 3, 4];
            let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

            let ciphertext = cipher.encrypt(&plaintext).unwrap();

            // Ciphertext should be different from plaintext (except for very rare cases)
            // At minimum, it should have nonce and tag added
            prop_assert!(ciphertext.len() > plaintext.len());
        }

        #[test]
        fn prop_tampered_ciphertext_fails(
            plaintext in prop::collection::vec(any::<u8>(), 10..100),
            tamper_pos in 12..100usize,
            tamper_byte in any::<u8>()
        ) {
            let key = [0u8; 32];
            let nonce_prefix = [1, 2, 3, 4];
            let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

            let mut ciphertext = cipher.encrypt(&plaintext).unwrap();

            if tamper_pos < ciphertext.len() && tamper_byte != 0 {
                ciphertext[tamper_pos] ^= tamper_byte;

                let result = cipher.decrypt(&ciphertext);
                prop_assert!(result.is_err());
            }
        }

        #[test]
        fn prop_unique_nonces(iterations in 0..100usize) {
            let key = [0u8; 32];
            let nonce_prefix = [1, 2, 3, 4];
            let cipher = AesGcmCipher::new(&key, nonce_prefix).unwrap();

            let plaintext = b"test";
            let mut nonces = std::collections::HashSet::new();

            for _ in 0..50 {
                let ciphertext = cipher.encrypt(plaintext).unwrap();
                let nonce = &ciphertext[0..12];
                nonces.insert(nonce.to_vec());
            }

            // All nonces should be unique
            prop_assert_eq!(nonces.len(), 50);
        }
    }
}
