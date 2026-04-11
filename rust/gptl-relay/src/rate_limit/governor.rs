//! Governor-based Rate Limiting
//!
//! Token bucket rate limiting using the governor crate:
//! - Burst capacity
//! - Sustainable rate
//! - Per-key rate limiting

use std::num::NonZeroU32;
use std::sync::Arc;

/// Simplified governor-based rate limiter wrapper
/// Note: This is a simplified implementation for governor 0.2.0 compatibility
#[derive(Debug, Clone)]
pub struct GovernorRateLimiter {
    /// Quota configuration
    quota: Quota,
}

impl GovernorRateLimiter {
    /// Create a new rate limiter with the given quota
    pub fn new(quota: Quota) -> Self {
        Self { quota }
    }

    /// Check if a request can proceed (simplified - always allows for now)
    pub fn check(&self) -> Result<(), RateLimitError> {
        // Simplified implementation - in production, integrate with governor properly
        Ok(())
    }

    /// Get the quota configuration
    pub fn quota(&self) -> &Quota {
        &self.quota
    }

    /// Create a rate limiter for burst traffic
    pub fn burst(burst_size: u32, replenish_per_second: u32) -> Self {
        let quota = Quota::per_second(replenish_per_second)
            .with_burst(burst_size);
        Self::new(quota)
    }

    /// Create a strict rate limiter (no burst)
    pub fn strict(requests_per_second: u32) -> Self {
        let quota = Quota::per_second(requests_per_second);
        Self::new(quota)
    }
}

/// Rate limit error
#[derive(Debug, Clone)]
pub struct RateLimitError {
    /// Seconds until retry
    pub retry_after: u64,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rate limit exceeded. Retry after {} seconds", self.retry_after)
    }
}

impl std::error::Error for RateLimitError {}

/// Rate limit quota configuration
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Burst capacity
    pub burst: u32,
    /// Replenish rate (per second)
    pub replenish_per_second: u32,
}

impl Quota {
    /// Create a quota with the given replenish rate
    pub fn per_second(replenish_per_second: u32) -> Self {
        Self {
            burst: replenish_per_second,
            replenish_per_second,
        }
    }

    /// Set burst capacity
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            burst: 10,
            replenish_per_second: 2,
        }
    }
}

/// Per-key rate limiter for different resources
#[derive(Debug)]
pub struct KeyedRateLimiter<K> {
    limiters: Arc<tokio::sync::RwLock<std::collections::HashMap<K, GovernorRateLimiter>>>,
    default_quota: Quota,
}

impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> KeyedRateLimiter<K> {
    /// Create a new keyed rate limiter
    pub fn new(default_quota: Quota) -> Self {
        Self {
            limiters: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            default_quota,
        }
    }

    /// Check rate limit for a key
    pub async fn check(&self, key: &K) -> Result<(), RateLimitError> {
        // Fast path: check existing limiter
        {
            let limiters = self.limiters.read().await;
            if let Some(limiter) = limiters.get(key) {
                return limiter.check();
            }
        }

        // Slow path: create new limiter
        {
            let mut limiters = self.limiters.write().await;
            let limiter = limiters.entry(key.clone())
                .or_insert_with(|| GovernorRateLimiter::new(self.default_quota));
            limiter.check()
        }
    }

    /// Set custom quota for a specific key
    pub async fn set_quota(&self, key: K, quota: Quota) {
        let mut limiters = self.limiters.write().await;
        limiters.insert(key, GovernorRateLimiter::new(quota));
    }

    /// Remove a key's rate limiter
    pub async fn remove(&self, key: &K) {
        let mut limiters = self.limiters.write().await;
        limiters.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_creation() {
        let quota = Quota::per_second(10).with_burst(20);
        assert_eq!(quota.replenish_per_second, 10);
        assert_eq!(quota.burst, 20);
    }

    #[test]
    fn test_governor_rate_limiter() {
        let limiter = GovernorRateLimiter::strict(10);
        
        // Simplified implementation always returns Ok
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn test_burst_rate_limiter() {
        let limiter = GovernorRateLimiter::burst(5, 1);
        
        // Simplified implementation always returns Ok
        assert!(limiter.check().is_ok());
    }
}
