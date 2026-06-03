//! Password hashing with Argon2id
use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier};

/// Upper bound on accepted password length. Argon2's pre-hash processes the
/// whole input, so an unauthenticated multi-megabyte "password" would burn relay
/// CPU on every login attempt; reject oversized inputs before hashing.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Password hasher
#[derive(Debug, Clone)]
pub struct PasswordHasher;

impl PasswordHasher {
    /// Create secure hasher
    pub fn secure() -> Self {
        Self
    }

    /// Hash password
    pub fn hash(&self, password: &str) -> crate::Result<String> {
        if password.len() > MAX_PASSWORD_LEN {
            return Err(crate::RelayError::Internal(format!(
                "password exceeds maximum length of {} bytes",
                MAX_PASSWORD_LEN
            )));
        }
        let salt = argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| crate::RelayError::Internal(format!("Hashing failed: {}", e)))?;
        Ok(hash.to_string())
    }

    /// Verify password
    pub fn verify(&self, password: &str, hash: &str) -> crate::Result<bool> {
        // Reject oversized input before running the (expensive) Argon2 verify, so
        // a huge password can't be used as a CPU-exhaustion vector on login.
        if password.len() > MAX_PASSWORD_LEN {
            return Ok(false);
        }
        let parsed = PasswordHash::new(hash)
            .map_err(|e| crate::RelayError::Internal(format!("Invalid hash: {}", e)))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::secure()
    }
}

/// Password strength checker
pub struct PasswordStrength;

impl PasswordStrength {
    /// Check if password meets requirements
    pub fn meets_requirements(password: &str) -> bool {
        let len = password.len();
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        len >= 12 && has_lowercase && has_uppercase && has_digit && has_special
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_roundtrip() {
        let h = PasswordHasher::secure();
        let hash = h.hash("Str0ng-Passw0rd!").unwrap();
        assert!(h.verify("Str0ng-Passw0rd!", &hash).unwrap());
        assert!(!h.verify("wrong", &hash).unwrap());
    }

    #[test]
    fn test_oversized_password_rejected() {
        let h = PasswordHasher::secure();
        let huge = "a".repeat(MAX_PASSWORD_LEN + 1);
        // hash() must error rather than burn CPU on a multi-KB input.
        assert!(h.hash(&huge).is_err());
        // verify() must short-circuit to false (no expensive Argon2 work).
        let valid_hash = h.hash("Str0ng-Passw0rd!").unwrap();
        assert!(!h.verify(&huge, &valid_hash).unwrap());
    }
}
