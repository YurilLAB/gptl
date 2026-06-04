//! ntor-lite handshake: X25519 + HKDF-SHA256 key agreement.
//!
//! # Protocol
//!
//! **CREATE cell payload (507 bytes):**
//!   [0..32]   SHA-256 of relay's static X25519 pubkey (fingerprint)
//!   [32..64]  client ephemeral X25519 pubkey
//!   [64..96]  client nonce (random 32 bytes)
//!   [96..507] reserved / zero
//!
//! **CREATED cell payload (507 bytes):**
//!   [0..32]   relay ephemeral X25519 pubkey
//!   [32..64]  relay nonce (random 32 bytes)
//!   [64..96]  key_confirmation = HMAC-SHA256(forward_key, "gptl-v1-confirm")
//!   [96..507] reserved / zero
//!
//! **Key derivation (ntor-style, two ECDH values):**
//!   dh1 = ECDH(client_ephemeral_priv, relay_static_pub)
//!   dh2 = ECDH(client_ephemeral_priv, relay_ephemeral_pub)
//!   ikm = dh1 || dh2 || relay_fingerprint  (96 bytes)
//!   salt = client_nonce || relay_nonce  (64 bytes)
//!   okm = HKDF-SHA256(ikm, salt=salt, info="gptl-transport-v1") → 64 bytes
//!   forward_key  = okm[0..32]   (client→relay AE key)
//!   backward_key = okm[32..64]  (relay→client AE key)
//!
//! `dh1` binds the session to possession of the relay's **static** private key,
//! which is what authenticates the relay and prevents a man-in-the-middle: an
//! attacker who does not hold the relay's static key cannot compute `dh1` and so
//! cannot derive `forward_key`/`backward_key` or forge the key confirmation.

use crate::{
    cell::{Cell, CellType},
    TransportError,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Derived session keys for one circuit direction.
pub struct SessionKeys {
    /// Client→relay ChaCha20Poly1305 key (32 bytes)
    pub forward_key: Zeroizing<[u8; 32]>,
    /// Relay→client ChaCha20Poly1305 key (32 bytes)
    pub backward_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("forward_key", &"<redacted>")
            .field("backward_key", &"<redacted>")
            .finish()
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        // zeroize::Zeroizing already handles cleanup on drop.
    }
}

// ── Client side ───────────────────────────────────────────────────────────────

/// State held by the client while waiting for the CREATED response.
pub struct PendingHandshake {
    relay_fingerprint: [u8; 32],
    /// Relay static public key — used for `dh1` (relay authentication).
    relay_static_pub: X25519Public,
    /// Client ephemeral private key. Held as a `StaticSecret` (not
    /// `EphemeralSecret`) because the ntor handshake performs **two** ECDH
    /// operations with it (against the relay's static and ephemeral keys);
    /// `EphemeralSecret::diffie_hellman` consumes the key after a single use.
    client_ephemeral_priv: StaticSecret,
    client_nonce: [u8; 32],
}

/// Begin a client handshake.
///
/// Returns the CREATE cell to send and the pending state to pass to `finish`.
pub fn client_initiate(
    circuit_id: u32,
    relay_static_pub: &[u8; 32],
) -> Result<(Cell, PendingHandshake), TransportError> {
    // Compute fingerprint (SHA-256 of relay static pubkey)
    let fingerprint = sha256(relay_static_pub);

    // Generate ephemeral keypair (StaticSecret so it can be used for two ECDHs)
    let ephemeral_priv = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = X25519Public::from(&ephemeral_priv);

    // Random client nonce
    let mut client_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce);

    // Build CREATE cell payload
    let mut cell = Cell::new(circuit_id, CellType::Create);
    cell.payload[0..32].copy_from_slice(&fingerprint);
    cell.payload[32..64].copy_from_slice(ephemeral_pub.as_bytes());
    cell.payload[64..96].copy_from_slice(&client_nonce);

    let relay_pub = X25519Public::from(*relay_static_pub);

    let state = PendingHandshake {
        relay_fingerprint: fingerprint,
        relay_static_pub: relay_pub,
        client_ephemeral_priv: ephemeral_priv,
        client_nonce,
    };

    Ok((cell, state))
}

/// Complete the handshake on receipt of the CREATED cell.
///
/// Returns derived `SessionKeys` or an error if the key confirmation fails.
pub fn client_finish(
    mut state: PendingHandshake,
    created: &Cell,
) -> Result<SessionKeys, TransportError> {
    if !matches!(created.cell_type, CellType::Created) {
        return Err(TransportError::Handshake("expected CREATED cell".into()));
    }

    let relay_ephemeral_pub_bytes: [u8; 32] = created.payload[0..32]
        .try_into()
        .map_err(|_| TransportError::Handshake("relay ephemeral pubkey truncated".into()))?;
    let relay_nonce: [u8; 32] = created.payload[32..64]
        .try_into()
        .map_err(|_| TransportError::Handshake("relay nonce truncated".into()))?;
    let received_confirmation: [u8; 32] = created.payload[64..96]
        .try_into()
        .map_err(|_| TransportError::Handshake("key confirmation truncated".into()))?;

    let relay_ephemeral_pub = X25519Public::from(relay_ephemeral_pub_bytes);

    // Two ECDH computations (ntor-style):
    //   dh1 = client_ephemeral · relay_static   → authenticates the relay
    //   dh2 = client_ephemeral · relay_ephemeral → forward secrecy
    let dh1 = state
        .client_ephemeral_priv
        .diffie_hellman(&state.relay_static_pub);
    let dh2 = state
        .client_ephemeral_priv
        .diffie_hellman(&relay_ephemeral_pub);

    // Reject low-order / non-contributory peer keys (all-zero shared secret).
    if !dh1.was_contributory() || !dh2.was_contributory() {
        return Err(TransportError::Handshake(
            "non-contributory ECDH (low-order relay key)".into(),
        ));
    }

    let keys = derive_keys_two_dh(
        dh1.as_bytes(),
        dh2.as_bytes(),
        &state.relay_fingerprint,
        &state.client_nonce,
        &relay_nonce,
    )?;

    // Verify key confirmation
    let expected = compute_confirmation(&keys.forward_key)?;
    if expected.ct_eq(&received_confirmation).unwrap_u8() != 1 {
        return Err(TransportError::Handshake(
            "key confirmation mismatch — relay authentication failed".into(),
        ));
    }

    Ok(keys)
}

// ── Relay side ────────────────────────────────────────────────────────────────

/// Static keypair for a relay node (loaded from disk at startup).
#[derive(Clone)]
pub struct RelayStaticKey {
    /// Private key (zeroized on drop)
    pub private: Zeroizing<[u8; 32]>,
    /// Public key (advertised in the directory)
    pub public: [u8; 32],
    /// SHA-256(public) — used as the relay fingerprint
    pub fingerprint: [u8; 32],
}

impl RelayStaticKey {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut priv_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(priv_bytes.as_mut());
        let secret = StaticSecret::from(*priv_bytes);
        let public = X25519Public::from(&secret);
        let pub_bytes = *public.as_bytes();
        Self {
            private: priv_bytes,
            public: pub_bytes,
            fingerprint: sha256(&pub_bytes),
        }
    }

    /// Load from raw 32-byte little-endian private key bytes.
    pub fn from_bytes(priv_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(priv_bytes);
        let public = X25519Public::from(&secret);
        let pub_bytes = *public.as_bytes();
        Self {
            private: Zeroizing::new(priv_bytes),
            public: pub_bytes,
            fingerprint: sha256(&pub_bytes),
        }
    }
}

impl std::fmt::Debug for RelayStaticKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayStaticKey")
            .field("fingerprint", &hex::encode(self.fingerprint))
            .field("public", &hex::encode(self.public))
            .finish()
    }
}

/// Process a CREATE cell and produce a CREATED cell + session keys.
pub fn relay_respond(
    create: &Cell,
    static_key: &RelayStaticKey,
) -> Result<(Cell, SessionKeys), TransportError> {
    if !matches!(create.cell_type, CellType::Create) {
        return Err(TransportError::Handshake("expected CREATE cell".into()));
    }

    // Parse CREATE payload — use map_err instead of unwrap for untrusted input
    let client_fp: [u8; 32] = create.payload[0..32].try_into().map_err(|_| {
        TransportError::Handshake("fingerprint field truncated in CREATE cell".into())
    })?;
    let client_ephemeral_pub_bytes: [u8; 32] = create.payload[32..64].try_into().map_err(|_| {
        TransportError::Handshake("ephemeral pubkey field truncated in CREATE cell".into())
    })?;
    let client_nonce: [u8; 32] = create.payload[64..96].try_into().map_err(|_| {
        TransportError::Handshake("client nonce field truncated in CREATE cell".into())
    })?;

    // Verify that the fingerprint matches our static key
    if client_fp.ct_eq(&static_key.fingerprint).unwrap_u8() != 1 {
        return Err(TransportError::Handshake(
            "CREATE cell fingerprint does not match this relay's identity".into(),
        ));
    }

    let client_ephemeral_pub = X25519Public::from(client_ephemeral_pub_bytes);

    // Generate relay ephemeral keypair
    let relay_ephemeral_priv = EphemeralSecret::random_from_rng(OsRng);
    let relay_ephemeral_pub = X25519Public::from(&relay_ephemeral_priv);

    // Two ECDH computations matching the client:
    //   dh1 = relay_static · client_ephemeral    → proves we hold the static key
    //   dh2 = relay_ephemeral · client_ephemeral → forward secrecy
    let relay_static_secret = StaticSecret::from(*static_key.private);
    let dh1 = relay_static_secret.diffie_hellman(&client_ephemeral_pub);
    let dh2 = relay_ephemeral_priv.diffie_hellman(&client_ephemeral_pub);

    // Reject low-order / non-contributory client keys (all-zero shared secret).
    if !dh1.was_contributory() || !dh2.was_contributory() {
        return Err(TransportError::Handshake(
            "non-contributory ECDH (low-order client key)".into(),
        ));
    }

    // Random relay nonce
    let mut relay_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut relay_nonce);

    // Derive keys (must produce same result as client_finish)
    let keys = derive_keys_two_dh(
        dh1.as_bytes(),
        dh2.as_bytes(),
        &static_key.fingerprint,
        &client_nonce,
        &relay_nonce,
    )?;

    // Compute key confirmation (HMAC over forward_key)
    let confirmation = compute_confirmation(&keys.forward_key)?;

    // Build CREATED cell
    let mut created = Cell::new(create.circuit_id, CellType::Created);
    created.payload[0..32].copy_from_slice(relay_ephemeral_pub.as_bytes());
    created.payload[32..64].copy_from_slice(&relay_nonce);
    created.payload[64..96].copy_from_slice(&confirmation);

    Ok((created, keys))
}

// ── Key derivation helpers ────────────────────────────────────────────────────

/// Derive forward_key and backward_key from the two ntor ECDH outputs plus the
/// relay's static-key fingerprint (identity binding).
fn derive_keys_two_dh(
    dh1_bytes: &[u8],
    dh2_bytes: &[u8],
    relay_fingerprint: &[u8; 32],
    client_nonce: &[u8; 32],
    relay_nonce: &[u8; 32],
) -> Result<SessionKeys, TransportError> {
    // IKM = dh1 || dh2 || relay_fingerprint (binds the relay's static identity)
    let mut ikm = Zeroizing::new(Vec::with_capacity(dh1_bytes.len() + dh2_bytes.len() + 32));
    ikm.extend_from_slice(dh1_bytes);
    ikm.extend_from_slice(dh2_bytes);
    ikm.extend_from_slice(relay_fingerprint);

    // Salt = client_nonce || relay_nonce
    let mut salt = [0u8; 64];
    salt[0..32].copy_from_slice(client_nonce);
    salt[32..64].copy_from_slice(relay_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"gptl-transport-v1", okm.as_mut())
        .map_err(|e| TransportError::Handshake(format!("HKDF expand failed: {}", e)))?;

    let mut fwd = Zeroizing::new([0u8; 32]);
    let mut bwd = Zeroizing::new([0u8; 32]);
    fwd.copy_from_slice(&okm[0..32]);
    bwd.copy_from_slice(&okm[32..64]);

    Ok(SessionKeys {
        forward_key: fwd,
        backward_key: bwd,
    })
}

fn compute_confirmation(forward_key: &[u8; 32]) -> Result<[u8; 32], TransportError> {
    let mut mac = HmacSha256::new_from_slice(forward_key)
        .map_err(|e| TransportError::Crypto(format!("HMAC init failed: {}", e)))?;
    mac.update(b"gptl-v1-confirm");
    Ok(mac.finalize().into_bytes().into())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a complete client↔relay handshake in-process.
    fn run_handshake(relay_key: &RelayStaticKey) -> (SessionKeys, SessionKeys) {
        let circuit_id = 1u32;
        let (create_cell, pending) = client_initiate(circuit_id, &relay_key.public).unwrap();
        let (created_cell, relay_keys) = relay_respond(&create_cell, relay_key).unwrap();
        let client_keys = client_finish(pending, &created_cell).unwrap();
        (client_keys, relay_keys)
    }

    #[test]
    fn test_handshake_succeeds_and_keys_match() {
        let relay_key = RelayStaticKey::generate();
        let (client_keys, relay_keys) = run_handshake(&relay_key);

        // forward_key (client→relay) must match on both sides
        assert_eq!(*client_keys.forward_key, *relay_keys.forward_key);
        // backward_key (relay→client) must match on both sides
        assert_eq!(*client_keys.backward_key, *relay_keys.backward_key);
    }

    #[test]
    fn test_different_relay_keys_produce_different_session_keys() {
        let relay1 = RelayStaticKey::generate();
        let relay2 = RelayStaticKey::generate();
        let (keys1, _) = run_handshake(&relay1);
        let (keys2, _) = run_handshake(&relay2);
        assert_ne!(*keys1.forward_key, *keys2.forward_key);
    }

    #[test]
    fn test_wrong_fingerprint_in_create_cell_rejected() {
        let relay_key = RelayStaticKey::generate();
        let (mut create_cell, _pending) = client_initiate(1, &relay_key.public).unwrap();
        // Corrupt the fingerprint in the CREATE payload
        create_cell.payload[0] ^= 0xFF;
        assert!(relay_respond(&create_cell, &relay_key).is_err());
    }

    #[test]
    fn test_tampered_created_cell_rejected_by_client() {
        let relay_key = RelayStaticKey::generate();
        let (create_cell, pending) = client_initiate(1, &relay_key.public).unwrap();
        let (mut created_cell, _relay_keys) = relay_respond(&create_cell, &relay_key).unwrap();
        // Corrupt the key confirmation bytes
        created_cell.payload[64] ^= 0xFF;
        assert!(client_finish(pending, &created_cell).is_err());
    }

    #[test]
    fn test_handshake_with_max_circuit_id() {
        let relay_key = RelayStaticKey::generate();
        let (create_cell, pending) = client_initiate(u32::MAX, &relay_key.public).unwrap();
        assert_eq!(create_cell.circuit_id, u32::MAX);
        let (created_cell, _) = relay_respond(&create_cell, &relay_key).unwrap();
        assert!(client_finish(pending, &created_cell).is_ok());
    }

    #[test]
    fn test_relay_static_key_from_bytes_roundtrip() {
        let key1 = RelayStaticKey::generate();
        let key2 = RelayStaticKey::from_bytes(*key1.private);
        assert_eq!(key1.public, key2.public);
        assert_eq!(key1.fingerprint, key2.fingerprint);
    }

    #[test]
    fn test_wrong_cell_type_rejected_by_relay() {
        let relay_key = RelayStaticKey::generate();
        let cell = Cell::new(1, CellType::Padding); // wrong type
        assert!(relay_respond(&cell, &relay_key).is_err());
    }

    #[test]
    fn test_wrong_cell_type_rejected_by_client() {
        let relay_key = RelayStaticKey::generate();
        let (create_cell, pending) = client_initiate(1, &relay_key.public).unwrap();
        let (created_cell, _) = relay_respond(&create_cell, &relay_key).unwrap();
        // Replace the cell type with Padding
        let mut buf = created_cell.to_bytes();
        buf[4] = CellType::Padding as u8;
        let bad_cell = Cell::from_bytes(&buf).unwrap();
        assert!(client_finish(pending, &bad_cell).is_err());
    }

    #[test]
    fn test_session_keys_are_not_all_zeros() {
        let relay_key = RelayStaticKey::generate();
        let (client_keys, _) = run_handshake(&relay_key);
        // Keys must not be all-zero (catastrophic KDF failure)
        assert_ne!(*client_keys.forward_key, [0u8; 32]);
        assert_ne!(*client_keys.backward_key, [0u8; 32]);
    }

    #[test]
    fn test_forward_and_backward_keys_differ() {
        let relay_key = RelayStaticKey::generate();
        let (client_keys, _) = run_handshake(&relay_key);
        // forward and backward keys must be different
        assert_ne!(*client_keys.forward_key, *client_keys.backward_key);
    }

    #[test]
    fn test_handshake_cannot_be_finished_twice() {
        let relay_key = RelayStaticKey::generate();
        let (create_cell, pending) = client_initiate(1, &relay_key.public).unwrap();
        let (created_cell, _) = relay_respond(&create_cell, &relay_key).unwrap();
        let _keys = client_finish(pending, &created_cell).unwrap();
        // pending is consumed (moved), so a second call is impossible at compile time.
    }

    #[test]
    fn test_each_handshake_produces_unique_keys() {
        let relay_key = RelayStaticKey::generate();
        let (keys1, _) = run_handshake(&relay_key);
        let (keys2, _) = run_handshake(&relay_key);
        assert_ne!(*keys1.forward_key, *keys2.forward_key);
        assert_ne!(*keys1.backward_key, *keys2.backward_key);
    }

    #[test]
    fn test_mitm_without_static_key_is_rejected() {
        // The relay the client intends to reach.
        let relay_key = RelayStaticKey::generate();
        let (create_cell, pending) = client_initiate(1, &relay_key.public).unwrap();

        // An active attacker observes the CREATE cell — it learns the client
        // ephemeral pubkey and the relay fingerprint (both public) but does NOT
        // know the relay's static private key.
        let client_eph_pub_bytes: [u8; 32] = create_cell.payload[32..64].try_into().unwrap();
        let client_eph_pub = X25519Public::from(client_eph_pub_bytes);
        let client_nonce: [u8; 32] = create_cell.payload[64..96].try_into().unwrap();

        // The attacker forges a CREATED cell using only an ephemeral×ephemeral DH
        // (the previously-broken single-DH scheme). It cannot compute
        // dh1 = client_ephemeral · relay_static without the static key, so it must
        // guess — here, the best it can do is a zero/garbage dh1.
        let atk_eph = EphemeralSecret::random_from_rng(OsRng);
        let atk_eph_pub = X25519Public::from(&atk_eph);
        let dh2 = atk_eph.diffie_hellman(&client_eph_pub);
        let fake_dh1 = [0u8; 32];
        let mut relay_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut relay_nonce);
        let forged_keys = derive_keys_two_dh(
            &fake_dh1,
            dh2.as_bytes(),
            &relay_key.fingerprint,
            &client_nonce,
            &relay_nonce,
        )
        .unwrap();
        let confirmation = compute_confirmation(&forged_keys.forward_key).unwrap();

        let mut forged = Cell::new(1, CellType::Created);
        forged.payload[0..32].copy_from_slice(atk_eph_pub.as_bytes());
        forged.payload[32..64].copy_from_slice(&relay_nonce);
        forged.payload[64..96].copy_from_slice(&confirmation);

        // The client derives the REAL dh1 using the relay's static pubkey, which
        // differs from the attacker's guess, so key confirmation must fail.
        assert!(
            client_finish(pending, &forged).is_err(),
            "MITM without the relay static key must be rejected"
        );
    }

    #[test]
    fn test_relay_respond_rejects_created_cell_type() {
        let relay_key = RelayStaticKey::generate();
        let cell = Cell::new(1, CellType::Created);
        assert!(relay_respond(&cell, &relay_key).is_err());
    }

    /// Fuzz: feeding random CREATE/CREATED cells to the handshake parsers must
    /// never panic — only succeed or return an error. (Stable toolchain, so a
    /// deterministic PRNG stands in for cargo-fuzz.)
    #[test]
    fn fuzz_handshake_parsers_never_panic() {
        let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let relay_key = RelayStaticKey::generate();

        let iters: usize = std::env::var("GPTL_FUZZ_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(|n: usize| n / 6) // handshake iters are heavier (keygen per loop)
            .unwrap_or(4_000);
        for _ in 0..iters {
            // Random CREATE cell into relay_respond.
            let mut create = Cell::new((next() & 0xffff_ffff) as u32, CellType::Create);
            for b in create.payload.iter_mut() {
                *b = (next() & 0xff) as u8;
            }
            let _ = relay_respond(&create, &relay_key);

            // Random CREATED cell into a fresh client_finish.
            let (_c, pending) = client_initiate(1, &relay_key.public).unwrap();
            let mut created = Cell::new(1, CellType::Created);
            for b in created.payload.iter_mut() {
                *b = (next() & 0xff) as u8;
            }
            let _ = client_finish(pending, &created);
        }
    }
}
