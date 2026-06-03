//! Governor-style Token Bucket Rate Limiting
//!
//! A self-contained token-bucket rate limiter with:
//!   * sustainable rate (`replenish_per_second`),
//!   * burst capacity,
//!   * per-key (`KeyedRateLimiter`) buckets.
//!
//! The previous implementation was a stub: `check()` always returned
//! `Ok(())`, meaning every caller bypassed rate limiting entirely. This
//! version computes a real bucket level using a continuous-time refill
//! model so it tolerates clock skips and idle periods.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

/// Token-bucket rate limiter.
#[derive(Debug)]
pub struct GovernorRateLimiter {
    quota: Quota,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl Clone for GovernorRateLimiter {
    fn clone(&self) -> Self {
        let s = self.state.lock().expect("bucket lock poisoned");
        Self {
            quota: self.quota,
            state: Mutex::new(BucketState {
                tokens: s.tokens,
                last_refill: s.last_refill,
            }),
        }
    }
}

impl GovernorRateLimiter {
    /// Create a new rate limiter with the given quota.  The bucket starts
    /// full (one full burst available immediately).
    pub fn new(quota: Quota) -> Self {
        Self {
            quota,
            state: Mutex::new(BucketState {
                tokens: quota.burst as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Check (and consume) one token.  Returns `Err` with the retry-after
    /// hint if the bucket is empty.
    pub fn check(&self) -> Result<(), RateLimitError> {
        let mut state = self.state.lock().expect("bucket lock poisoned");
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.quota.replenish_per_second as f64)
            .min(self.quota.burst as f64);
        state.last_refill = now;

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            // How long until at least one full token replenishes.
            let deficit = 1.0 - state.tokens;
            let seconds = if self.quota.replenish_per_second == 0 {
                u64::MAX
            } else {
                (deficit / self.quota.replenish_per_second as f64).ceil() as u64
            };
            Err(RateLimitError {
                retry_after: seconds.max(1),
            })
        }
    }

    /// Get the quota configuration
    pub fn quota(&self) -> &Quota {
        &self.quota
    }

    /// Create a rate limiter for burst traffic
    pub fn burst(burst_size: u32, replenish_per_second: u32) -> Self {
        let quota = Quota::per_second(replenish_per_second).with_burst(burst_size);
        Self::new(quota)
    }

    /// Create a strict rate limiter (burst == replenish rate).
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
        write!(
            f,
            "Rate limit exceeded. Retry after {} seconds",
            self.retry_after
        )
    }
}

impl std::error::Error for RateLimitError {}

/// Rate limit quota configuration
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Burst capacity (max tokens in the bucket)
    pub burst: u32,
    /// Replenish rate (tokens added per second)
    pub replenish_per_second: u32,
}

impl Quota {
    /// Create a quota with the given replenish rate (burst == rate by default).
    pub fn per_second(replenish_per_second: u32) -> Self {
        Self {
            burst: replenish_per_second,
            replenish_per_second,
        }
    }

    /// Set burst capacity.
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
            let limiter = limiters
                .entry(key.clone())
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
    fn test_governor_burst_then_throttle() {
        // burst=3, refill=1/s: first 3 requests pass, 4th fails.
        let limiter = GovernorRateLimiter::new(Quota {
            burst: 3,
            replenish_per_second: 1,
        });
        assert!(limiter.check().is_ok(), "1st request must pass (burst)");
        assert!(limiter.check().is_ok(), "2nd request must pass (burst)");
        assert!(limiter.check().is_ok(), "3rd request must pass (burst)");
        assert!(limiter.check().is_err(), "4th request must be rate-limited");
    }

    #[test]
    fn test_governor_strict_rejects_second_request() {
        let limiter = GovernorRateLimiter::strict(1);
        assert!(limiter.check().is_ok());
        assert!(
            limiter.check().is_err(),
            "strict(1) must reject a second back-to-back request"
        );
    }

    #[test]
    fn test_governor_replenishes_over_time() {
        let limiter = GovernorRateLimiter::new(Quota {
            burst: 1,
            replenish_per_second: 1000,
        });
        assert!(limiter.check().is_ok());
        // 5ms is well over 1/1000s — bucket should refill.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(
            limiter.check().is_ok(),
            "must allow after enough time has elapsed for a refill"
        );
    }

    #[tokio::test]
    async fn test_keyed_rate_limiter_independent_buckets() {
        let kl: KeyedRateLimiter<&'static str> = KeyedRateLimiter::new(Quota {
            burst: 1,
            replenish_per_second: 0,
        });
        assert!(kl.check(&"a").await.is_ok());
        assert!(
            kl.check(&"b").await.is_ok(),
            "different keys must have independent buckets"
        );
        assert!(
            kl.check(&"a").await.is_err(),
            "same key must reuse the bucket"
        );
    }
}
