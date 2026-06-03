//! GPTL Cryptographic Module
//!
//! Provides cryptographic primitives for the GPTL anonymity network:
//! - Cell encryption/decryption (AES-256-GCM, ChaCha20-Poly1305)
//! - Key exchange protocols (X25519, hybrid X25519+ML-KEM-768)
//! - Forward secrecy with key ratcheting
//! - Post-quantum cryptography (ML-KEM-768)
//!
//! Based on 2025-2026 best practices:
//! - NIST FIPS 203 (ML-KEM)
//! - IETF hybrid key exchange drafts
//! - aws-lc-rs for FIPS-validated implementations

#![warn(missing_docs)]

pub mod aead;
pub mod kex;
pub mod ratchet;

use std::time::Duration;

pub use aead::{AesGcmCipher, CellCipher, ChaCha20Cipher};
pub use kex::{HybridKeyExchange, KeyExchange, X25519KeyExchange};
pub use ratchet::ForwardSecrecy;

/// Cryptographic configuration
#[derive(Debug, Clone)]
pub struct CryptoConfig {
    /// Cell cipher algorithm
    pub cell_cipher: CipherSuite,
    /// Key exchange algorithm
    pub key_exchange: KeyExchangeAlgorithm,
    /// Enable forward secrecy
    pub forward_secrecy: bool,
    /// Key rotation interval
    pub key_rotation_interval: Duration,
}

/// Cipher suite for cell encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// AES-256-GCM (recommended for hardware with AES-NI)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (recommended for software-only or mobile)
    ChaCha20Poly1305,
}

/// Key exchange algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeAlgorithm {
    /// X25519 (Elliptic Curve Diffie-Hellman)
    X25519,
    /// Hybrid X25519+ML-KEM-768 (post-quantum resistant)
    HybridX25519Kyber768,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            // AES-256-GCM is now preferred on modern CPUs with AES-NI (2025-2026)
            cell_cipher: CipherSuite::Aes256Gcm,
            // Hybrid key exchange for quantum resistance
            key_exchange: KeyExchangeAlgorithm::HybridX25519Kyber768,
            forward_secrecy: true,
            // Rotate keys every 2 minutes for high-security applications
            key_rotation_interval: Duration::from_secs(120),
        }
    }
}

/// Public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<u8>);

/// Private key (zeroized on drop)
#[derive(Clone)]
pub struct PrivateKey(pub zeroize::Zeroizing<Vec<u8>>);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrivateKey").field(&"<redacted>").finish()
    }
}

/// Shared secret (zeroized on drop)
#[derive(Clone)]
pub struct SharedSecret(pub zeroize::Zeroizing<Vec<u8>>);

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedSecret").field(&"<redacted>").finish()
    }
}

/// Cell encryption error
#[derive(Debug, thiserror::Error)]
pub enum CellEncryptionError {
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length in bytes
        expected: usize,
        /// Actual key length in bytes
        actual: usize,
    },
    /// Invalid nonce
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),
    /// Nonce exhausted (counter overflow)
    #[error("Nonce counter exhausted - key rotation required")]
    NonceExhausted,
}

/// Key exchange error
#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeError {
    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    /// Invalid private key
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    /// Shared secret computation failed
    #[error("Shared secret computation failed: {0}")]
    SharedSecretFailed(String),
}

/// Cryptographic utilities
pub mod utils {
    use subtle::ConstantTimeEq;

    /// Constant-time comparison using subtle crate
    ///
    /// This is the recommended approach for 2025-2026 to prevent timing attacks.
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        a.ct_eq(b).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];

        assert!(utils::constant_time_eq(&a, &b));
        assert!(!utils::constant_time_eq(&a, &c));
    }

    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.cell_cipher, CipherSuite::Aes256Gcm);
        assert_eq!(
            config.key_exchange,
            KeyExchangeAlgorithm::HybridX25519Kyber768
        );
        assert!(config.forward_secrecy);
    }
}
