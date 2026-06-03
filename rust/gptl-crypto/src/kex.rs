//! Key Exchange implementations
//!
//! Provides X25519 and hybrid X25519+ML-KEM-768 key exchange.
//! Based on NIST FIPS 203 and IETF hybrid key exchange drafts (2025-2026).
//!
//! # Hybrid KEM usage
//!
//! The hybrid key exchange uses KEM semantics (not symmetric DH):
//! - **Initiator**: calls `encapsulate(recipient_pk)` → sends `EncapsulationResult::ciphertext`
//! - **Responder**: calls `decapsulate(own_private, ciphertext)` → same shared secret
//!
//! Ciphertext payload layout: `ephemeral_X25519_pk (32 B) || ML-KEM-768 ciphertext (1088 B)`

use crate::{KeyExchangeError, PrivateKey, PublicKey, SharedSecret};
use aws_lc_rs::hkdf;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Key exchange trait
pub trait KeyExchange: Send + Sync {
    /// Generate ephemeral keypair
    fn generate_keypair(&self) -> Result<(PublicKey, PrivateKey), KeyExchangeError>;

    /// Compute shared secret
    fn compute_shared(
        &self,
        private: &PrivateKey,
        public: &PublicKey,
    ) -> Result<SharedSecret, KeyExchangeError>;
}

/// X25519 key exchange implementation
///
/// Classical elliptic curve Diffie-Hellman on Curve25519.
/// Still recommended for 2025-2026 but consider hybrid for quantum resistance.
pub struct X25519KeyExchange;

impl X25519KeyExchange {
    /// Create new X25519 key exchange
    pub fn new() -> Self {
        Self
    }
}

impl Default for X25519KeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange for X25519KeyExchange {
    fn generate_keypair(&self) -> Result<(PublicKey, PrivateKey), KeyExchangeError> {
        // Generate random bytes for the secret key
        let mut secret_bytes = [0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut secret_bytes);

        let secret = StaticSecret::from(secret_bytes);
        let public = X25519PublicKey::from(&secret);

        Ok((
            PublicKey(public.as_bytes().to_vec()),
            PrivateKey(Zeroizing::new(secret.to_bytes().to_vec())),
        ))
    }

    fn compute_shared(
        &self,
        private: &PrivateKey,
        public: &PublicKey,
    ) -> Result<SharedSecret, KeyExchangeError> {
        if private.0.len() != 32 {
            return Err(KeyExchangeError::InvalidPrivateKey(format!(
                "Expected 32 bytes, got {}",
                private.0.len()
            )));
        }

        if public.0.len() != 32 {
            return Err(KeyExchangeError::InvalidPublicKey(format!(
                "Expected 32 bytes, got {}",
                public.0.len()
            )));
        }

        let secret_bytes: [u8; 32] = private.0[..]
            .try_into()
            .map_err(|_| KeyExchangeError::InvalidPrivateKey("Invalid length".to_string()))?;
        let secret = StaticSecret::from(secret_bytes);

        let public_bytes: [u8; 32] = public.0[..]
            .try_into()
            .map_err(|_| KeyExchangeError::InvalidPublicKey("Invalid length".to_string()))?;
        let public_key = X25519PublicKey::from(public_bytes);

        let shared = secret.diffie_hellman(&public_key);

        // Reject non-contributory key exchange: a low-order/zero peer public key
        // drives the X25519 output to all zeros, giving the peer a predictable
        // shared secret. was_contributory() is false in exactly that case.
        if !shared.was_contributory() {
            return Err(KeyExchangeError::InvalidPublicKey(
                "non-contributory X25519 public key (low-order point)".to_string(),
            ));
        }

        Ok(SharedSecret(Zeroizing::new(shared.as_bytes().to_vec())))
    }
}

/// Hybrid X25519 + ML-KEM-768 key exchange
///
/// Provides quantum resistance by combining classical and post-quantum algorithms.
/// Security holds as long as one algorithm remains unbroken.
/// Based on IETF draft-ietf-tls-ecdhe-mlkem and NIST FIPS 203.
pub struct HybridKeyExchange {
    x25519: X25519KeyExchange,
}

impl HybridKeyExchange {
    /// Create new hybrid key exchange
    pub fn new() -> Self {
        Self {
            x25519: X25519KeyExchange::new(),
        }
    }
}

impl Default for HybridKeyExchange {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a KEM encapsulation operation
///
/// The `ciphertext` must be sent to the decapsulating party.
/// The `shared_secret` is used by the encapsulating (initiator) party.
pub struct EncapsulationResult {
    /// KEM ciphertext: ephemeral X25519 public key (32 B) || ML-KEM-768 ciphertext (1088 B)
    pub ciphertext: Vec<u8>,
    /// Shared secret — matches what `decapsulate` returns for the same ciphertext
    pub shared_secret: SharedSecret,
}

impl HybridKeyExchange {
    /// Encapsulate: initiator calls this with the recipient's public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.  Send `ciphertext` to the recipient;
    /// keep `shared_secret` as the session key.
    ///
    /// Ciphertext layout: `ephemeral_X25519_pk (32 B) || ML-KEM-768_ct (1088 B)`
    pub fn encapsulate(
        &self,
        recipient_public: &PublicKey,
    ) -> Result<EncapsulationResult, KeyExchangeError> {
        const X25519_PUBLIC_LEN: usize = 32;
        const KYBER768_PUBLIC_LEN: usize = 1184;

        if recipient_public.0.len() != X25519_PUBLIC_LEN + KYBER768_PUBLIC_LEN {
            return Err(KeyExchangeError::InvalidPublicKey(format!(
                "Expected {} bytes, got {}",
                X25519_PUBLIC_LEN + KYBER768_PUBLIC_LEN,
                recipient_public.0.len()
            )));
        }

        // X25519: generate ephemeral keypair and compute DH with recipient
        let (ephemeral_pub, ephemeral_priv) = self.x25519.generate_keypair()?;
        let recipient_x25519_pub = PublicKey(recipient_public.0[..X25519_PUBLIC_LEN].to_vec());
        let x25519_shared = self
            .x25519
            .compute_shared(&ephemeral_priv, &recipient_x25519_pub)?;

        // ML-KEM-768: encapsulate to recipient's public key
        let kyber_pub_bytes = &recipient_public.0[X25519_PUBLIC_LEN..];
        let kyber_public = pqcrypto_kyber::kyber768::PublicKey::from_bytes(kyber_pub_bytes)
            .map_err(|_| {
                KeyExchangeError::InvalidPublicKey("ML-KEM public key parse error".to_string())
            })?;
        // Note: pqcrypto-kyber returns (SharedSecret, Ciphertext) — not (Ciphertext, SharedSecret)
        let (kyber_shared, kyber_ct) = pqcrypto_kyber::kyber768::encapsulate(&kyber_public);

        // Combine: HKDF(x25519_shared || mlkem_shared) per IETF draft-ietf-tls-ecdhe-mlkem
        let shared_secret =
            Self::combine_shared_secrets(&x25519_shared.0, kyber_shared.as_bytes())?;

        // Ciphertext: ephemeral X25519 pk || ML-KEM ciphertext
        let mut ciphertext = ephemeral_pub.0.clone();
        ciphertext.extend_from_slice(kyber_ct.as_bytes());

        Ok(EncapsulationResult {
            ciphertext,
            shared_secret,
        })
    }

    /// Decapsulate: responder calls this with their own private key and the received ciphertext.
    ///
    /// `ciphertext` is the value from `EncapsulationResult::ciphertext`.
    /// Returns the same shared secret as the encapsulating party.
    pub fn decapsulate(
        &self,
        own_private: &PrivateKey,
        ciphertext: &[u8],
    ) -> Result<SharedSecret, KeyExchangeError> {
        const X25519_EPHEMERAL_LEN: usize = 32;
        const KYBER768_CT_LEN: usize = 1088;
        const X25519_PRIVATE_LEN: usize = 32;
        const KYBER768_PRIVATE_LEN: usize = 2400;

        if ciphertext.len() != X25519_EPHEMERAL_LEN + KYBER768_CT_LEN {
            return Err(KeyExchangeError::InvalidPublicKey(format!(
                "Ciphertext expected {} bytes, got {}",
                X25519_EPHEMERAL_LEN + KYBER768_CT_LEN,
                ciphertext.len()
            )));
        }

        if own_private.0.len() != X25519_PRIVATE_LEN + KYBER768_PRIVATE_LEN {
            return Err(KeyExchangeError::InvalidPrivateKey(format!(
                "Expected {} bytes, got {}",
                X25519_PRIVATE_LEN + KYBER768_PRIVATE_LEN,
                own_private.0.len()
            )));
        }

        // X25519: DH with ephemeral initiator public key
        let ephemeral_x25519_pub = PublicKey(ciphertext[..X25519_EPHEMERAL_LEN].to_vec());
        let x25519_private =
            PrivateKey(Zeroizing::new(own_private.0[..X25519_PRIVATE_LEN].to_vec()));
        let x25519_shared = self
            .x25519
            .compute_shared(&x25519_private, &ephemeral_x25519_pub)?;

        // ML-KEM-768: decapsulate using own secret key
        let kyber_ct_bytes = &ciphertext[X25519_EPHEMERAL_LEN..];
        let kyber_private_bytes = &own_private.0[X25519_PRIVATE_LEN..];
        let kyber_ct =
            pqcrypto_kyber::kyber768::Ciphertext::from_bytes(kyber_ct_bytes).map_err(|_| {
                KeyExchangeError::InvalidPublicKey("ML-KEM ciphertext parse error".to_string())
            })?;
        let kyber_sk = pqcrypto_kyber::kyber768::SecretKey::from_bytes(kyber_private_bytes)
            .map_err(|_| {
                KeyExchangeError::InvalidPrivateKey("ML-KEM secret key parse error".to_string())
            })?;
        let kyber_shared = pqcrypto_kyber::kyber768::decapsulate(&kyber_ct, &kyber_sk);

        Self::combine_shared_secrets(&x25519_shared.0, kyber_shared.as_bytes())
    }

    /// Combine X25519 and ML-KEM shared secrets using HKDF-SHA256.
    ///
    /// Uses concatenation as IKM per IETF draft-ietf-tls-ecdhe-mlkem:
    /// `HKDF(salt=0, IKM=x25519_shared||mlkem_shared, info="hybrid-shared-secret")`
    fn combine_shared_secrets(
        x25519: &[u8],
        mlkem: &[u8],
    ) -> Result<SharedSecret, KeyExchangeError> {
        let mut ikm = x25519.to_vec();
        ikm.extend_from_slice(mlkem);

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&ikm);
        let mut output = [0u8; 32];
        prk.expand(&[b"hybrid-shared-secret"], hkdf::HKDF_SHA256)
            .map_err(|_| KeyExchangeError::SharedSecretFailed("HKDF expand failed".to_string()))?
            .fill(&mut output)
            .map_err(|_| KeyExchangeError::SharedSecretFailed("HKDF fill failed".to_string()))?;

        Ok(SharedSecret(Zeroizing::new(output.to_vec())))
    }
}

impl KeyExchange for HybridKeyExchange {
    fn generate_keypair(&self) -> Result<(PublicKey, PrivateKey), KeyExchangeError> {
        // Generate X25519 keypair
        let (x25519_public, x25519_private) = self.x25519.generate_keypair()?;

        // Generate ML-KEM-768 keypair
        let (kyber_public, kyber_private) = pqcrypto_kyber::kyber768::keypair();

        // Public key: X25519 pk (32 B) || ML-KEM-768 pk (1184 B)
        let mut combined_public = x25519_public.0;
        combined_public.extend_from_slice(kyber_public.as_bytes());

        // Private key: X25519 sk (32 B) || ML-KEM-768 sk (2400 B)
        let mut combined_private = x25519_private.0.to_vec();
        combined_private.extend_from_slice(kyber_private.as_bytes());

        Ok((
            PublicKey(combined_public),
            PrivateKey(Zeroizing::new(combined_private)),
        ))
    }

    /// Not meaningful for hybrid KEM — use `encapsulate`/`decapsulate` instead.
    ///
    /// This method is present only to satisfy the trait. It returns an error
    /// because a KEM requires asymmetric initiator/responder roles that cannot
    /// be expressed through the symmetric `compute_shared` interface.
    fn compute_shared(
        &self,
        _private: &PrivateKey,
        _public: &PublicKey,
    ) -> Result<SharedSecret, KeyExchangeError> {
        Err(KeyExchangeError::SharedSecretFailed(
            "Hybrid KEM requires separate encapsulate/decapsulate calls. \
             Use HybridKeyExchange::encapsulate (initiator) and \
             HybridKeyExchange::decapsulate (responder)."
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        let kex = X25519KeyExchange::new();

        // Alice generates keypair
        let (alice_public, alice_private) = kex.generate_keypair().unwrap();

        // Bob generates keypair
        let (bob_public, bob_private) = kex.generate_keypair().unwrap();

        // Alice computes shared secret
        let alice_shared = kex.compute_shared(&alice_private, &bob_public).unwrap();

        // Bob computes shared secret
        let bob_shared = kex.compute_shared(&bob_private, &alice_public).unwrap();

        // Shared secrets should match
        assert_eq!(alice_shared.0.as_slice(), bob_shared.0.as_slice());
    }

    #[test]
    fn test_hybrid_key_exchange_encap_decap() {
        let kex = HybridKeyExchange::new();

        // Bob generates a long-term keypair (recipient)
        let (bob_public, bob_private) = kex.generate_keypair().unwrap();

        // Verify key sizes
        assert_eq!(bob_public.0.len(), 32 + 1184); // X25519 + ML-KEM-768 pk
        assert_eq!(bob_private.0.len(), 32 + 2400); // X25519 + ML-KEM-768 sk

        // Alice (initiator) encapsulates to Bob's public key
        let encap = kex.encapsulate(&bob_public).unwrap();

        // Ciphertext: ephemeral X25519 pk (32) + ML-KEM ct (1088)
        assert_eq!(encap.ciphertext.len(), 32 + 1088);

        // Bob (responder) decapsulates
        let bob_shared = kex.decapsulate(&bob_private, &encap.ciphertext).unwrap();

        // Both shared secrets must match
        assert_eq!(encap.shared_secret.0.as_slice(), bob_shared.0.as_slice());

        // Shared secret should be 32 bytes (HKDF-SHA256 output)
        assert_eq!(bob_shared.0.len(), 32);

        // Shared secret must not be all zeros
        assert!(bob_shared.0.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hybrid_keypair_uniqueness() {
        let kex = HybridKeyExchange::new();
        let (pub1, _) = kex.generate_keypair().unwrap();
        let (pub2, _) = kex.generate_keypair().unwrap();
        assert_ne!(pub1.0, pub2.0);
    }

    #[test]
    fn test_hybrid_different_encapsulations_produce_different_secrets() {
        let kex = HybridKeyExchange::new();
        let (bob_public, _bob_private) = kex.generate_keypair().unwrap();

        // Two separate encapsulations to the same key should produce different secrets
        let encap1 = kex.encapsulate(&bob_public).unwrap();
        let encap2 = kex.encapsulate(&bob_public).unwrap();

        assert_ne!(
            encap1.shared_secret.0.as_slice(),
            encap2.shared_secret.0.as_slice()
        );
        assert_ne!(encap1.ciphertext, encap2.ciphertext);
    }

    #[test]
    fn test_hybrid_wrong_private_key_produces_different_secret() {
        let kex = HybridKeyExchange::new();
        let (bob_public, _bob_private) = kex.generate_keypair().unwrap();
        let (_other_public, other_private) = kex.generate_keypair().unwrap();

        let encap = kex.encapsulate(&bob_public).unwrap();

        // Decapsulating with wrong private key should produce a different (incorrect) secret
        let wrong_shared = kex.decapsulate(&other_private, &encap.ciphertext).unwrap();
        assert_ne!(encap.shared_secret.0.as_slice(), wrong_shared.0.as_slice());
    }

    #[test]
    fn test_x25519_keypair_uniqueness() {
        let kex = X25519KeyExchange::new();

        let (pub1, _) = kex.generate_keypair().unwrap();
        let (pub2, _) = kex.generate_keypair().unwrap();

        // Public keys should be different
        assert_ne!(pub1.0, pub2.0);
    }

    #[test]
    fn test_x25519_shared_secret_consistency() {
        let kex = X25519KeyExchange::new();

        let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
        let (bob_pub, bob_priv) = kex.generate_keypair().unwrap();

        // Compute shared secret multiple times
        let shared1 = kex.compute_shared(&alice_priv, &bob_pub).unwrap();
        let shared2 = kex.compute_shared(&alice_priv, &bob_pub).unwrap();

        // Should be deterministic
        assert_eq!(shared1.0.as_slice(), shared2.0.as_slice());
    }

    #[test]
    fn test_x25519_invalid_public_key() {
        let kex = X25519KeyExchange::new();
        let (_pub, priv_key) = kex.generate_keypair().unwrap();

        // An all-zero public key is a low-order point: the DH output is all
        // zeros (non-contributory), which must be rejected rather than producing
        // a predictable shared secret.
        let invalid_pub = PublicKey(vec![0u8; 32]);
        let result = kex.compute_shared(&priv_key, &invalid_pub);
        assert!(
            result.is_err(),
            "all-zero (low-order) public key must be rejected"
        );

        // A wrong-length public key is also rejected.
        assert!(kex
            .compute_shared(&priv_key, &PublicKey(vec![0u8; 31]))
            .is_err());
    }

    #[test]
    fn test_key_sizes() {
        let kex_x25519 = X25519KeyExchange::new();
        let (pub_key, priv_key) = kex_x25519.generate_keypair().unwrap();

        assert_eq!(pub_key.0.len(), 32);
        assert_eq!(priv_key.0.len(), 32);

        let kex_hybrid = HybridKeyExchange::new();
        let (pub_hybrid, priv_hybrid) = kex_hybrid.generate_keypair().unwrap();

        // X25519 (32) + Kyber768 public key (1184)
        assert_eq!(pub_hybrid.0.len(), 32 + 1184);
        // X25519 (32) + Kyber768 secret key (2400)
        assert_eq!(priv_hybrid.0.len(), 32 + 2400);
    }

    #[test]
    fn test_shared_secret_not_all_zeros() {
        let kex = X25519KeyExchange::new();
        let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
        let (bob_pub, _) = kex.generate_keypair().unwrap();

        let shared = kex.compute_shared(&alice_priv, &bob_pub).unwrap();

        // Shared secret should not be all zeros
        assert!(shared.0.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_public_key_serialization() {
        let kex = X25519KeyExchange::new();
        let (pub_key, _) = kex.generate_keypair().unwrap();

        // Serialize and deserialize
        let bytes = pub_key.0.clone();
        let restored = PublicKey(bytes);

        assert_eq!(pub_key.0, restored.0);
    }

    #[test]
    fn test_x25519_empty_private_key_rejected() {
        let kex = X25519KeyExchange::new();
        let (bob_pub, _) = kex.generate_keypair().unwrap();

        let empty_priv = PrivateKey(zeroize::Zeroizing::new(vec![]));
        let result = kex.compute_shared(&empty_priv, &bob_pub);
        assert!(result.is_err(), "empty private key should be rejected");
    }

    #[test]
    fn test_x25519_wrong_length_private_key_rejected() {
        let kex = X25519KeyExchange::new();
        let (bob_pub, _) = kex.generate_keypair().unwrap();

        // 16 bytes instead of 32
        let short_priv = PrivateKey(zeroize::Zeroizing::new(vec![0xAA; 16]));
        let result = kex.compute_shared(&short_priv, &bob_pub);
        assert!(
            result.is_err(),
            "wrong-length private key should be rejected"
        );
    }

    #[test]
    fn test_x25519_wrong_length_public_key_rejected() {
        let kex = X25519KeyExchange::new();
        let (_, alice_priv) = kex.generate_keypair().unwrap();

        // 16 bytes instead of 32
        let short_pub = PublicKey(vec![0xBB; 16]);
        let result = kex.compute_shared(&alice_priv, &short_pub);
        assert!(
            result.is_err(),
            "wrong-length public key should be rejected"
        );
    }

    #[test]
    fn test_x25519_key_reuse_produces_same_secret() {
        // Key reuse with the same pair must always give same result (deterministic)
        let kex = X25519KeyExchange::new();
        let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
        let (bob_pub, bob_priv) = kex.generate_keypair().unwrap();

        let s1 = kex.compute_shared(&alice_priv, &bob_pub).unwrap();
        let s2 = kex.compute_shared(&alice_priv, &bob_pub).unwrap();
        let s3 = kex.compute_shared(&bob_priv, &alice_pub).unwrap();

        assert_eq!(
            s1.0.as_slice(),
            s2.0.as_slice(),
            "repeated calls with same keys must match"
        );
        assert_eq!(
            s1.0.as_slice(),
            s3.0.as_slice(),
            "symmetric shared secret must match"
        );
    }

    #[test]
    fn test_x25519_different_keypairs_produce_different_secrets() {
        let kex = X25519KeyExchange::new();
        let (alice_pub, _) = kex.generate_keypair().unwrap();
        let (_, priv1) = kex.generate_keypair().unwrap();
        let (_, priv2) = kex.generate_keypair().unwrap();

        let s1 = kex.compute_shared(&priv1, &alice_pub).unwrap();
        let s2 = kex.compute_shared(&priv2, &alice_pub).unwrap();

        assert_ne!(
            s1.0.as_slice(),
            s2.0.as_slice(),
            "different private keys with same public key must produce different secrets"
        );
    }

    #[test]
    fn test_x25519_all_zero_shared_secret_is_suspicious() {
        // A legitimate X25519 exchange should not produce an all-zero shared secret.
        // This is a sanity check: if both endpoints are real random keys the probability is negligible.
        let kex = X25519KeyExchange::new();
        let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
        let (bob_pub, _) = kex.generate_keypair().unwrap();

        let shared = kex.compute_shared(&alice_priv, &bob_pub).unwrap();
        assert!(
            shared.0.iter().any(|&b| b != 0),
            "shared secret from random keypairs must not be all-zero"
        );
    }

    #[test]
    fn test_hybrid_empty_ciphertext_rejected() {
        let kex = HybridKeyExchange::new();
        let (_, bob_private) = kex.generate_keypair().unwrap();

        let result = kex.decapsulate(&bob_private, &[]);
        assert!(result.is_err(), "empty ciphertext must be rejected");
    }

    #[test]
    fn test_hybrid_wrong_length_ciphertext_rejected() {
        let kex = HybridKeyExchange::new();
        let (_, bob_private) = kex.generate_keypair().unwrap();

        // Only 32 bytes, needs 32 + 1088 = 1120
        let short_ct = vec![0u8; 32];
        let result = kex.decapsulate(&bob_private, &short_ct);
        assert!(result.is_err(), "short ciphertext must be rejected");
    }

    #[test]
    fn test_hybrid_compute_shared_returns_error() {
        // compute_shared is not meaningful for hybrid KEM; must return Err
        let kex = HybridKeyExchange::new();
        let (pub_key, priv_key) = kex.generate_keypair().unwrap();
        let result = kex.compute_shared(&priv_key, &pub_key);
        assert!(
            result.is_err(),
            "HybridKeyExchange::compute_shared must return Err (use encapsulate/decapsulate)"
        );
    }

    #[test]
    fn test_hybrid_shared_secret_not_all_zeros() {
        let kex = HybridKeyExchange::new();
        let (bob_public, bob_private) = kex.generate_keypair().unwrap();

        let encap = kex.encapsulate(&bob_public).unwrap();
        let bob_shared = kex.decapsulate(&bob_private, &encap.ciphertext).unwrap();

        assert!(
            bob_shared.0.iter().any(|&b| b != 0),
            "hybrid shared secret must not be all-zero"
        );
    }

    #[test]
    fn test_hybrid_unique_secrets_across_keypairs() {
        let kex = HybridKeyExchange::new();
        let (pub1, priv1) = kex.generate_keypair().unwrap();
        let (pub2, priv2) = kex.generate_keypair().unwrap();

        // Alice encapsulates to Bob
        let encap1 = kex.encapsulate(&pub2).unwrap();
        // Bob decapsulates
        let secret1 = kex.decapsulate(&priv2, &encap1.ciphertext).unwrap();

        // Charlie encapsulates to Dave
        let encap2 = kex.encapsulate(&pub1).unwrap();
        let secret2 = kex.decapsulate(&priv1, &encap2.ciphertext).unwrap();

        assert_ne!(
            secret1.0.as_slice(),
            secret2.0.as_slice(),
            "secrets from different keypair exchanges must differ"
        );
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_x25519_shared_secret_symmetric(_seed1 in any::<u64>(), _seed2 in any::<u64>()) {
            let kex = X25519KeyExchange::new();

            // Generate two keypairs
            let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
            let (bob_pub, bob_priv) = kex.generate_keypair().unwrap();

            // Compute shared secrets both ways
            let alice_shared = kex.compute_shared(&alice_priv, &bob_pub).unwrap();
            let bob_shared = kex.compute_shared(&bob_priv, &alice_pub).unwrap();

            // Must be equal
            prop_assert_eq!(alice_shared.0.as_slice(), bob_shared.0.as_slice());
        }

        #[test]
        fn prop_keypair_uniqueness(_iterations in 0..100usize) {
            let kex = X25519KeyExchange::new();
            let mut public_keys = std::collections::HashSet::new();

            for _ in 0..10 {
                let (pub_key, _) = kex.generate_keypair().unwrap();
                public_keys.insert(pub_key.0.clone());
            }

            // All public keys should be unique
            prop_assert_eq!(public_keys.len(), 10);
        }

        #[test]
        fn prop_shared_secret_length(_seed in any::<u64>()) {
            let kex = X25519KeyExchange::new();
            let (alice_pub, alice_priv) = kex.generate_keypair().unwrap();
            let (bob_pub, _) = kex.generate_keypair().unwrap();

            let shared = kex.compute_shared(&alice_priv, &bob_pub).unwrap();

            // Shared secret should always be 32 bytes
            prop_assert_eq!(shared.0.len(), 32);
        }
    }
}
