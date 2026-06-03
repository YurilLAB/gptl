//! TOTP Implementation — RFC 6238 (HMAC-SHA1, 30s step, 6 digits)
//!
//! Uses the `totp-rs` crate (already in our dependency tree) for the actual
//! HOTP computation; we provide a thin wrapper that enforces:
//!   * base32-encoded secret material (per RFC 6238),
//!   * a configurable verification window for clock-skew tolerance,
//!   * cryptographically random per-user backup codes,
//!   * constant-time code comparison (delegated to totp-rs internals).

use base32::{encode as base32_encode_lib, Alphabet};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{RelayError, Result};

/// TOTP manager.  `time_step` defaults to 30s and `digits` to 6 per RFC 6238.
#[derive(Debug, Clone)]
pub struct TotpManager {
    time_step: u64,
    digits: usize,
    /// Tolerated codes per side (e.g. 1 = accept previous, current, next step).
    drift_steps: u8,
    /// Last successfully-consumed time step per secret, to prevent code reuse
    /// (RFC 6238 §5.2). Shared across clones so replay state is global.
    used_steps: Arc<Mutex<HashMap<String, u64>>>,
}

impl Default for TotpManager {
    fn default() -> Self {
        Self {
            time_step: 30,
            digits: 6,
            drift_steps: 1,
            used_steps: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl TotpManager {
    /// Verify a 6-digit TOTP code against a base32-encoded secret.
    ///
    /// Returns `Ok(true)` only if the supplied `code` matches the value
    /// derived from `secret_b32` at the current Unix time (with
    /// `drift_steps` of tolerance).  The previous implementation was a
    /// stub that returned `Ok(true)` for every input — the entire second
    /// factor of MFA was bypassed.
    pub fn verify(&self, secret_b32: &str, code: &str) -> Result<bool> {
        if code.len() != self.digits {
            return Ok(false);
        }
        // `Secret::Encoded` interprets the input as base32 (RFC 4648).
        let secret_bytes = Secret::Encoded(secret_b32.to_string())
            .to_bytes()
            .map_err(|e| RelayError::ConfigError(format!("TOTP secret: {:?}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            self.digits,
            self.drift_steps,
            self.time_step,
            secret_bytes,
            Some("GPTL".to_string()),
            "GPTL".to_string(),
        )
        .map_err(|e| RelayError::ConfigError(format!("TOTP build: {:?}", e)))?;

        // `check_current` does a constant-time compare across the drift window.
        if !totp
            .check_current(code)
            .map_err(|e| RelayError::ConfigError(format!("TOTP check: {:?}", e)))?
        {
            return Ok(false);
        }

        // The code is valid for the current window. Enforce single-use per
        // RFC 6238 §5.2: identify which time step it matched and reject it if
        // that step (or an earlier one) was already consumed for this secret.
        // Otherwise a code captured (e.g. via shoulder-surf or a logged request)
        // could be replayed for the whole +/- drift window.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RelayError::ConfigError(format!("clock: {:?}", e)))?
            .as_secs();
        let current_step = now / self.time_step;
        let drift = self.drift_steps as i64;

        let mut matched_step: Option<u64> = None;
        // Search newest step first so we record the most recent match.
        for k in (-drift..=drift).rev() {
            let step = match (current_step as i64).checked_add(k) {
                Some(s) if s >= 0 => s as u64,
                _ => continue,
            };
            let candidate = totp.generate(step * self.time_step);
            if candidate.as_bytes().ct_eq(code.as_bytes()).into() {
                matched_step = Some(step);
                break;
            }
        }

        // If we cannot localize the step (should not happen after check_current
        // passed), fail closed rather than allow a possible replay.
        let matched_step = match matched_step {
            Some(s) => s,
            None => return Ok(false),
        };

        let mut used = self
            .used_steps
            .lock()
            .map_err(|_| RelayError::ConfigError("TOTP replay lock poisoned".into()))?;
        if let Some(&last) = used.get(secret_b32) {
            if matched_step <= last {
                return Ok(false); // replay of an already-used (or older) code
            }
        }
        used.insert(secret_b32.to_string(), matched_step);
        Ok(true)
    }

    /// Setup TOTP for a user — produces a fresh 20-byte secret, a valid
    /// `otpauth://` provisioning URI, and 10 cryptographically random
    /// 10-digit backup codes.
    pub async fn setup_for_user(&self, user_id: &str) -> Result<TotpSetup> {
        let secret = generate_secret();
        let b32 = base32_encode_lib(Alphabet::Rfc4648 { padding: false }, &secret);
        let provisioning_uri = format!(
            "otpauth://totp/GPTL:{}?secret={}&issuer=GPTL&algorithm=SHA1&digits={}&period={}",
            user_id, b32, self.digits, self.time_step,
        );

        Ok(TotpSetup {
            secret: b32,
            provisioning_uri,
            backup_codes: generate_backup_codes(),
            qr_code_data: None,
        })
    }
}

/// TOTP setup
#[derive(Debug, Clone)]
pub struct TotpSetup {
    pub secret: String,
    pub provisioning_uri: String,
    pub backup_codes: Vec<String>,
    pub qr_code_data: Option<String>,
}

fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    secret
}

/// Ten cryptographically-random 10-digit backup codes.
///
/// The previous implementation returned `format!("{:09}", i * 123456789 % 1e9)`
/// for `i in 0..10` — every user got the same enumerable set, trivially
/// computable by anyone with the source.  These are now drawn from OS entropy.
fn generate_backup_codes() -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..10)
        .map(|_| format!("{:010}", rng.gen_range(0..10_000_000_000u64)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_totp_rejects_invalid_code() {
        let mgr = TotpManager::default();
        let setup = mgr.setup_for_user("alice").await.unwrap();
        // "000000" is overwhelmingly unlikely to be the current valid code.
        let result = mgr.verify(&setup.secret, "000000").unwrap();
        assert!(
            !result,
            "TOTP must reject a fixed wrong code (was a stub returning Ok(true))"
        );
    }

    #[tokio::test]
    async fn test_totp_code_cannot_be_replayed() {
        let mgr = TotpManager::default();
        let setup = mgr.setup_for_user("carol").await.unwrap();

        // Compute the current valid code the same way the manager does.
        let secret_bytes = Secret::Encoded(setup.secret.clone()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("GPTL".to_string()),
            "GPTL".to_string(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        assert!(
            mgr.verify(&setup.secret, &code).unwrap(),
            "first use must be accepted"
        );
        assert!(
            !mgr.verify(&setup.secret, &code).unwrap(),
            "the same code must not be accepted twice (replay)"
        );
    }

    #[tokio::test]
    async fn test_totp_rejects_wrong_length() {
        let mgr = TotpManager::default();
        let setup = mgr.setup_for_user("bob").await.unwrap();
        assert!(!mgr.verify(&setup.secret, "12345").unwrap());
        assert!(!mgr.verify(&setup.secret, "1234567").unwrap());
        assert!(!mgr.verify(&setup.secret, "").unwrap());
    }

    #[tokio::test]
    async fn test_backup_codes_are_random_per_user() {
        let mgr = TotpManager::default();
        let a = mgr.setup_for_user("a").await.unwrap();
        let b = mgr.setup_for_user("b").await.unwrap();
        assert_ne!(
            a.backup_codes, b.backup_codes,
            "backup codes must not be a deterministic function of position"
        );
        let unique: std::collections::HashSet<_> = a.backup_codes.iter().collect();
        assert_eq!(unique.len(), 10, "all 10 backup codes must be unique");
    }

    #[tokio::test]
    async fn test_provisioning_uri_uses_base32_not_base64() {
        let mgr = TotpManager::default();
        let setup = mgr.setup_for_user("eve").await.unwrap();
        // Base32 alphabet is A-Z and 2-7; base64 includes lowercase, '+' and '/'.
        for c in setup.secret.chars() {
            assert!(
                c.is_ascii_uppercase() || ('2'..='7').contains(&c),
                "secret must be RFC 4648 base32; saw {:?}",
                c,
            );
        }
    }
}
