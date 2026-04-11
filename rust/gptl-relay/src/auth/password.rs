//! Password hashing with Argon2id
use argon2::{Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier};

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
        let salt = argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| crate::RelayError::Internal(format!("Hashing failed: {}", e)))?;
        Ok(hash.to_string())
    }

    /// Verify password
    pub fn verify(&self, password: &str, hash: &str) -> crate::Result<bool> {
        let parsed = PasswordHash::new(hash)
            .map_err(|e| crate::RelayError::Internal(format!("Invalid hash: {}", e)))?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
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
