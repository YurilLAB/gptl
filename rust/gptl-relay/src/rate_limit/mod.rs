//! Rate Limiting and Anti-Brute Force Protection
//!
//! Implements multi-layer rate limiting inspired by SSH and enterprise systems:
//! - Per-IP rate limiting with token bucket
//! - Per-account rate limiting
//! - Exponential backoff on failed auth
//! - Account lockout after N failures
//! - CAPTCHA challenges

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::RwLock;

pub mod governor;
pub mod captcha;

pub use governor::{GovernorRateLimiter, Quota};
pub use captcha::{CaptchaChallenge, CaptchaGenerator, CaptchaVerification};

/// Main rate limiter combining all protection mechanisms
#[derive(Debug)]
pub struct AuthRateLimiter {
    /// Per-IP rate limiting
    ip_limiter: Arc<RwLock<HashMap<IpAddr, IpRateLimitState>>>,
    /// Per-account rate limiting
    account_limiter: Arc<RwLock<HashMap<String, AccountRateLimitState>>>,
    /// Failed attempt tracking per IP
    ip_failures: Arc<RwLock<HashMap<IpAddr, FailureRecord>>>,
    /// Failed attempt tracking per account
    account_failures: Arc<RwLock<HashMap<String, FailureRecord>>>,
    /// Locked accounts
    locked_accounts: Arc<RwLock<HashMap<String, AccountLockoutEntry>>>,
    /// Configuration
    config: RateLimitConfig,
}

impl AuthRateLimiter {
    /// Create a new rate limiter with default configuration
    pub fn new() -> Self {
        Self::with_config(RateLimitConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            ip_limiter: Arc::new(RwLock::new(HashMap::new())),
            account_limiter: Arc::new(RwLock::new(HashMap::new())),
            ip_failures: Arc::new(RwLock::new(HashMap::new())),
            account_failures: Arc::new(RwLock::new(HashMap::new())),
            locked_accounts: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if an IP is rate limited
    pub async fn check_ip(&self, ip: IpAddr) -> crate::Result<()> {
        self.cleanup_expired().await;

        let mut limiter = self.ip_limiter.write().await;
        let state = limiter.entry(ip).or_insert_with(IpRateLimitState::new);

        // Check if in exponential backoff
        if let Some(backoff_until) = state.backoff_until {
            if backoff_until > Utc::now() {
                let wait_secs = (backoff_until - Utc::now()).num_seconds() as u64;
                return Err(crate::RelayError::RateLimitExceeded(wait_secs));
            }
        }

        // Check rate limit
        if state.requests >= self.config.max_requests_per_ip {
            // Calculate backoff
            let backoff = self.calculate_backoff(state.consecutive_failures);
            state.backoff_until = Some(Utc::now() + backoff);
            
            return Err(crate::RelayError::RateLimitExceeded(backoff.num_seconds() as u64));
        }

        state.requests += 1;
        state.last_request = Utc::now();

        Ok(())
    }

    /// Check if an account is rate limited
    pub async fn check_account(&self, username: &str) -> crate::Result<()> {
        self.cleanup_expired().await;

        // Check if account is locked
        {
            let locked = self.locked_accounts.read().await;
            if let Some(lockout) = locked.get(username) {
                if lockout.expires_at > Utc::now() {
                    let remaining = (lockout.expires_at - Utc::now()).num_seconds() as u64;
                    return Err(crate::RelayError::AccountLocked(
                        format!("Account locked for {} more seconds", remaining)
                    ));
                }
            }
        }

        let mut limiter = self.account_limiter.write().await;
        let state = limiter.entry(username.to_string()).or_insert_with(AccountRateLimitState::new);

        if state.requests >= self.config.max_requests_per_account {
            let wait_secs = self.config.account_rate_limit_window_secs;
            return Err(crate::RelayError::RateLimitExceeded(wait_secs));
        }

        state.requests += 1;
        state.last_request = Utc::now();

        Ok(())
    }

    /// Record a successful authentication
    pub async fn record_success(&self, ip: IpAddr, username: &str) {
        // Reset IP failure count
        {
            let mut failures = self.ip_failures.write().await;
            failures.remove(&ip);
        }

        // Reset account failure count
        {
            let mut failures = self.account_failures.write().await;
            failures.remove(username);
        }

        // Reset IP rate limit backoff
        {
            let mut limiter = self.ip_limiter.write().await;
            if let Some(state) = limiter.get_mut(&ip) {
                state.consecutive_failures = 0;
                state.backoff_until = None;
            }
        }
    }

    /// Record a failed authentication
    pub async fn record_failure(&self, ip: IpAddr, username: &str) -> FailureAction {
        let now = Utc::now();

        // Update IP failure record
        let ip_failure_count = {
            let mut failures = self.ip_failures.write().await;
            let record = failures.entry(ip).or_insert_with(FailureRecord::new);
            record.count += 1;
            record.last_failure = now;
            record.count
        };

        // Update account failure record
        let account_failure_count = {
            let mut failures = self.account_failures.write().await;
            let record = failures.entry(username.to_string()).or_insert_with(FailureRecord::new);
            record.count += 1;
            record.last_failure = now;
            record.count
        };

        // Update IP rate limit state
        {
            let mut limiter = self.ip_limiter.write().await;
            let state = limiter.entry(ip).or_insert_with(IpRateLimitState::new);
            state.consecutive_failures += 1;
        }

        // Check if account should be locked
        if account_failure_count >= self.config.account_lockout_threshold {
            let lockout_duration = self.calculate_lockout_duration(account_failure_count);
            
            let mut locked = self.locked_accounts.write().await;
            locked.insert(username.to_string(), AccountLockoutEntry {
                username: username.to_string(),
                locked_at: now,
                expires_at: now + lockout_duration,
                failure_count: account_failure_count,
            });

            return FailureAction::AccountLocked {
                duration_secs: lockout_duration.num_seconds() as u64,
            };
        }

        // Check if CAPTCHA is required
        if ip_failure_count >= self.config.captcha_threshold {
            return FailureAction::CaptchaRequired;
        }

        // Check if exponential backoff should be applied
        if ip_failure_count >= self.config.backoff_threshold {
            let backoff = self.calculate_backoff(ip_failure_count);
            
            let mut limiter = self.ip_limiter.write().await;
            if let Some(state) = limiter.get_mut(&ip) {
                state.backoff_until = Some(now + backoff);
            }

            return FailureAction::ExponentialBackoff {
                wait_secs: backoff.num_seconds() as u64,
            };
        }

        FailureAction::None
    }

    /// Check if account is locked
    pub async fn is_account_locked(&self, username: &str) -> Option<AccountLockoutInfo> {
        let locked = self.locked_accounts.read().await;
        
        locked.get(username).map(|lockout| {
            let remaining = (lockout.expires_at - Utc::now()).num_seconds().max(0) as u64;
            AccountLockoutInfo {
                locked: true,
                remaining_secs: remaining,
                unlocks_at: lockout.expires_at,
            }
        })
    }

    /// Unlock an account (admin operation)
    pub async fn unlock_account(&self, username: &str) -> crate::Result<()> {
        let mut locked = self.locked_accounts.write().await;
        locked.remove(username);
        
        // Also clear failure count
        let mut failures = self.account_failures.write().await;
        failures.remove(username);
        
        Ok(())
    }

    /// Get failure statistics for an IP
    pub async fn get_ip_stats(&self, ip: IpAddr) -> IpFailureStats {
        let failures = self.ip_failures.read().await;
        let limiter = self.ip_limiter.read().await;
        
        let failure_count = failures.get(&ip).map(|f| f.count).unwrap_or(0);
        let consecutive_failures = limiter.get(&ip).map(|s| s.consecutive_failures).unwrap_or(0);
        let in_backoff = limiter.get(&ip)
            .and_then(|s| s.backoff_until)
            .map(|t| t > Utc::now())
            .unwrap_or(false);

        IpFailureStats {
            failure_count,
            consecutive_failures,
            in_backoff,
            captcha_required: failure_count >= self.config.captcha_threshold,
        }
    }

    /// Calculate exponential backoff duration.
    ///
    /// At `backoff_threshold` failures the first backoff is 2^1 = 2 s,
    /// at `threshold + 1` it is 2^2 = 4 s, etc.
    fn calculate_backoff(&self, failures: u32) -> Duration {
        let exponent = failures.saturating_sub(self.config.backoff_threshold) + 1;
        let seconds = (2u32.pow(exponent.min(10)) as i64) // Cap at 2^10 = 1024 seconds
            .min(self.config.max_backoff_secs as i64);

        Duration::seconds(seconds)
    }

    /// Calculate account lockout duration
    fn calculate_lockout_duration(&self, failures: u32) -> Duration {
        // Progressive lockout: starts at 15 minutes, doubles each time, caps at 24 hours
        let base_duration = Duration::minutes(15);
        let multiplier = 2u32.pow((failures / self.config.account_lockout_threshold).min(5));
        let max_duration = Duration::hours(24);
        
        (base_duration * multiplier as i32).min(max_duration)
    }

    /// Cleanup expired entries
    async fn cleanup_expired(&self) {
        let cutoff = Utc::now() - Duration::hours(24);
        
        // Cleanup IP failures
        {
            let mut failures = self.ip_failures.write().await;
            failures.retain(|_, record| record.last_failure > cutoff);
        }

        // Cleanup account failures
        {
            let mut failures = self.account_failures.write().await;
            failures.retain(|_, record| record.last_failure > cutoff);
        }

        // Cleanup expired lockouts
        {
            let mut locked = self.locked_accounts.write().await;
            let now = Utc::now();
            locked.retain(|_, lockout| lockout.expires_at > now);
        }

        // Cleanup old rate limit entries
        {
            let mut limiter = self.ip_limiter.write().await;
            limiter.retain(|_, state| state.last_request > cutoff);
        }
    }
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per IP per window
    pub max_requests_per_ip: u32,
    /// IP rate limit window in seconds
    pub ip_rate_limit_window_secs: i64,
    /// Maximum requests per account per window
    pub max_requests_per_account: u32,
    /// Account rate limit window in seconds
    pub account_rate_limit_window_secs: u64,
    /// Number of failures before exponential backoff
    pub backoff_threshold: u32,
    /// Maximum backoff duration in seconds
    pub max_backoff_secs: u32,
    /// Number of failures before CAPTCHA
    pub captcha_threshold: u32,
    /// Number of failures before account lockout
    pub account_lockout_threshold: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_ip: 10,
            ip_rate_limit_window_secs: 60,
            max_requests_per_account: 5,
            account_rate_limit_window_secs: 60,
            backoff_threshold: 3,
            max_backoff_secs: 3600,
            captcha_threshold: 5,
            account_lockout_threshold: 10,
        }
    }
}

/// IP rate limit state
#[derive(Debug)]
struct IpRateLimitState {
    requests: u32,
    last_request: DateTime<Utc>,
    consecutive_failures: u32,
    backoff_until: Option<DateTime<Utc>>,
}

impl IpRateLimitState {
    fn new() -> Self {
        Self {
            requests: 0,
            last_request: Utc::now(),
            consecutive_failures: 0,
            backoff_until: None,
        }
    }
}

/// Account rate limit state
#[derive(Debug)]
struct AccountRateLimitState {
    requests: u32,
    last_request: DateTime<Utc>,
}

impl AccountRateLimitState {
    fn new() -> Self {
        Self {
            requests: 0,
            last_request: Utc::now(),
        }
    }
}

/// Failure record
#[derive(Debug, Clone)]
struct FailureRecord {
    count: u32,
    last_failure: DateTime<Utc>,
}

impl FailureRecord {
    fn new() -> Self {
        Self {
            count: 0,
            last_failure: Utc::now(),
        }
    }
}

/// Account lockout entry
#[derive(Debug, Clone)]
struct AccountLockoutEntry {
    username: String,
    locked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    failure_count: u32,
}

/// Action to take after a failure
#[derive(Debug, Clone)]
pub enum FailureAction {
    /// No special action
    None,
    /// Require CAPTCHA
    CaptchaRequired,
    /// Apply exponential backoff
    ExponentialBackoff { wait_secs: u64 },
    /// Lock the account
    AccountLocked { duration_secs: u64 },
}

/// Account lockout information
#[derive(Debug, Clone)]
pub struct AccountLockoutInfo {
    pub locked: bool,
    pub remaining_secs: u64,
    pub unlocks_at: DateTime<Utc>,
}

/// IP failure statistics
#[derive(Debug, Clone)]
pub struct IpFailureStats {
    pub failure_count: u32,
    pub consecutive_failures: u32,
    pub in_backoff: bool,
    pub captcha_required: bool,
}

/// Lockout configuration
#[derive(Debug, Clone)]
pub struct LockoutConfig {
    /// Failure threshold for lockout
    pub failure_threshold: u32,
    /// Base lockout duration in seconds
    pub base_duration_secs: u64,
    /// Maximum lockout duration in seconds
    pub max_duration_secs: u64,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            base_duration_secs: 900,  // 15 minutes
            max_duration_secs: 86400, // 24 hours
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_config() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests_per_ip, 10);
        assert_eq!(config.backoff_threshold, 3);
        assert_eq!(config.captcha_threshold, 5);
    }

    #[tokio::test]
    async fn test_failure_action_progression() {
        let limiter = AuthRateLimiter::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let username = "testuser";

        // First 2 failures: No action
        for _ in 0..2 {
            let action = limiter.record_failure(ip, username).await;
            assert!(matches!(action, FailureAction::None));
        }

        // 3rd failure: Backoff
        let action = limiter.record_failure(ip, username).await;
        assert!(matches!(action, FailureAction::ExponentialBackoff { .. }));

        // Reset limiter state
        limiter.record_success(ip, username).await;
        
        // Test CAPTCHA threshold
        for _ in 0..5 {
            limiter.record_failure(ip, username).await;
        }
        let action = limiter.record_failure(ip, username).await;
        assert!(matches!(action, FailureAction::CaptchaRequired));
    }

    #[test]
    fn test_backoff_calculation() {
        let limiter = AuthRateLimiter::new();
        
        // Test exponential growth
        let b1 = limiter.calculate_backoff(3);
        assert_eq!(b1.num_seconds(), 2); // 2^1
        
        let b2 = limiter.calculate_backoff(4);
        assert_eq!(b2.num_seconds(), 4); // 2^2
        
        let b3 = limiter.calculate_backoff(5);
        assert_eq!(b3.num_seconds(), 8); // 2^3
    }
}
