//! Timing Protection Module
//!
//! Implements countermeasures against timing attacks including jitter injection,
//! batching, and constant-rate transmission to prevent timing correlation attacks.

use super::{AntiSurveillanceConfig, AntiSurveillanceError, Cell};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rand::Rng;
use rand_distr::{Distribution, Normal, Poisson};

/// Timing shield for protecting against timing analysis
pub struct TimingShield {
    config: Arc<RwLock<AntiSurveillanceConfig>>,
    /// Reorder buffer
    reorder_buffer: Arc<RwLock<VecDeque<TimestampedCell>>>,
    /// Batching buffer
    batch_buffer: Arc<RwLock<Vec<Cell>>>,
}

/// Cell with timing information
#[derive(Debug, Clone)]
struct TimestampedCell {
    cell: Cell,
    original_time: Instant,
    scheduled_time: Instant,
}

impl TimingShield {
    /// Create new timing shield
    pub fn new(config: Arc<RwLock<AntiSurveillanceConfig>>) -> Self {
        let reorder_buffer = Arc::new(RwLock::new(VecDeque::new()));
        let batch_buffer = Arc::new(RwLock::new(Vec::new()));
        
        Self {
            config,
            reorder_buffer,
            batch_buffer,
        }
    }

    /// Initialize timing protection
    pub async fn initialize(&self) -> Result<(), AntiSurveillanceError> {
        Ok(())
    }

    /// Protect timing of outgoing cells
    pub async fn protect_timing(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let config = self.config.read().await;
        
        match config.level {
            super::SecurityLevel::Standard => {
                // Basic jitter only
                self.add_jitter(cells, Duration::from_millis(5)).await
            }
            super::SecurityLevel::Enhanced => {
                // Jitter + light batching
                let jittered = self.add_jitter(cells, Duration::from_millis(20)).await?;
                self.batch_cells(jittered, 5, Duration::from_millis(50)).await
            }
            super::SecurityLevel::Maximum => {
                // Full protection: jitter + batching + reordering
                let jittered = self.add_jitter(cells, Duration::from_millis(config.max_jitter_ms)).await?;
                let batched = self.batch_cells(jittered, config.batch_size, Duration::from_millis(100)).await?;
                self.reorder_cells(batched, 20).await
            }
        }
    }

    /// Add random jitter to cell timing
    async fn add_jitter(&self, cells: Vec<Cell>, max_jitter: Duration) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();
        
        // Use Poisson distribution for jitter (more realistic)
        let jitter_dist = Poisson::new(max_jitter.as_millis() as f64 / 2.0)
            .unwrap_or_else(|_| Poisson::new(10.0).unwrap());
        
        for cell in cells {
            // Sample jitter from distribution
            let jitter_ms: u64 = jitter_dist.sample(&mut rng) as u64;
            let jitter = Duration::from_millis(jitter_ms.min(max_jitter.as_millis() as u64));
            
            tokio::time::sleep(jitter).await;
            output.push(cell);
        }
        
        Ok(output)
    }

    /// Batch cells together
    async fn batch_cells(
        &self,
        cells: Vec<Cell>,
        batch_size: usize,
        max_wait: Duration,
    ) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut buffer = self.batch_buffer.write().await;
        let mut output = Vec::new();
        
        for cell in cells {
            buffer.push(cell);
            
            if buffer.len() >= batch_size {
                // Shuffle batch before output
                let mut batch: Vec<_> = buffer.drain(..).collect();
                self.shuffle_batch(&mut batch).await;
                output.extend(batch);
            }
        }
        
        // Handle remaining cells after timeout
        if !buffer.is_empty() {
            tokio::time::sleep(max_wait).await;
            let mut batch: Vec<_> = buffer.drain(..).collect();
            self.shuffle_batch(&mut batch).await;
            output.extend(batch);
        }
        
        Ok(output)
    }

    /// Reorder cells in buffer
    async fn reorder_cells(&self, cells: Vec<Cell>, buffer_size: usize) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut buffer = self.reorder_buffer.write().await;
        let mut output = Vec::new();
        
        for cell in cells {
            // Add to reorder buffer with scheduled time
            let now = Instant::now();
            let scheduled = now + Duration::from_millis(rand::random::<u64>() % 50);
            
            buffer.push_back(TimestampedCell {
                cell,
                original_time: now,
                scheduled_time: scheduled,
            });
            
            // Release cells that are ready
            while let Some(front) = buffer.front() {
                if front.scheduled_time <= Instant::now() || buffer.len() >= buffer_size {
                    if let Some(tc) = buffer.pop_front() {
                        output.push(tc.cell);
                    }
                } else {
                    break;
                }
            }
        }
        
        // Flush remaining cells
        while let Some(tc) = buffer.pop_front() {
            output.push(tc.cell);
        }
        
        Ok(output)
    }

    /// Shuffle batch randomly
    async fn shuffle_batch(&self, batch: &mut Vec<Cell>) {
        let mut rng = rand::thread_rng();
        
        // Fisher-Yates shuffle
        for i in (1..batch.len()).rev() {
            let j = rng.gen_range(0..=i);
            batch.swap(i, j);
        }
    }

    /// Normalize timing to fixed rate
    pub async fn normalize_rate(
        &self,
        cells: Vec<Cell>,
        target_rate: f64,
    ) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let interval = Duration::from_secs_f64(1.0 / target_rate);
        let mut output = Vec::new();
        
        for cell in cells {
            tokio::time::sleep(interval).await;
            output.push(cell);
        }
        
        Ok(output)
    }

    /// Apply Gaussian noise to timing
    pub fn add_gaussian_noise(
        &self,
        timestamp: Instant,
        std_dev_ms: f64,
    ) -> Result<Instant, AntiSurveillanceError> {
        let mut rng = rand::thread_rng();
        
        let normal = Normal::new(0.0, std_dev_ms)
            .map_err(|e| AntiSurveillanceError::TimingError(format!("Normal distribution error: {}", e)))?;
        
        let noise_ms = normal.sample(&mut rng);
        let noise_duration = Duration::from_millis(noise_ms.abs() as u64);
        
        if noise_ms >= 0.0 {
            Ok(timestamp + noise_duration)
        } else {
            // Ensure we don't go before the original timestamp
            Ok(timestamp.checked_sub(noise_duration).unwrap_or(timestamp))
        }
    }
}

/// Clock skew protection
/// Defends against clock skew fingerprinting attacks
pub struct ClockSkewProtection {
    /// Synthetic clock offset (can be negative)
    offset_ms: i64,
    /// Offset update interval
    update_interval: Duration,
    /// Last update time
    last_update: Instant,
}

impl ClockSkewProtection {
    /// Create new clock skew protection
    pub fn new() -> Self {
        Self {
            offset_ms: 0,
            update_interval: Duration::from_secs(60),
            last_update: Instant::now(),
        }
    }

    /// Get current time with synthetic offset
    pub fn now(&mut self) -> Instant {
        self.update_offset();
        let now = Instant::now();

        if self.offset_ms >= 0 {
            now + Duration::from_millis(self.offset_ms as u64)
        } else {
            now.checked_sub(Duration::from_millis((-self.offset_ms) as u64))
                .unwrap_or(now)
        }
    }

    /// Update synthetic offset periodically
    fn update_offset(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= self.update_interval {
            // Randomize offset to prevent fingerprinting
            let mut rng = rand::thread_rng();
            self.offset_ms = rng.gen_range(-100..100);
            self.last_update = now;
        }
    }

    /// Get TCP timestamp with protection
    pub fn tcp_timestamp(&mut self) -> u32 {
        // Return synthetic timestamp based on system uptime
        let now = Instant::now();
        let base_ts = now.elapsed().as_millis() as u32;

        // Apply offset
        if self.offset_ms >= 0 {
            base_ts.wrapping_add(self.offset_ms as u32)
        } else {
            base_ts.wrapping_sub((-self.offset_ms) as u32)
        }
    }
}

/// Watermark detection
/// Detects and mitigates timing watermarks
pub struct WatermarkDetector {
    /// Pattern detection window
    window_size: usize,
    /// Detected watermark patterns
    detected_patterns: Arc<RwLock<Vec<Vec<Duration>>>>,
}

impl WatermarkDetector {
    /// Create new watermark detector
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            detected_patterns: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Analyze timing pattern for watermarks
    pub async fn analyze_pattern(&self, timestamps: Vec<Instant>) -> bool {
        if timestamps.len() < self.window_size {
            return false;
        }

        // Calculate inter-arrival times
        let iats: Vec<Duration> = timestamps.windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .collect();

        // Check for regular patterns (potential watermarks)
        let has_pattern = self.detect_regular_pattern(&iats);
        
        if has_pattern {
            let mut patterns = self.detected_patterns.write().await;
            // Prevent unbounded growth by limiting stored patterns
            const MAX_PATTERNS: usize = 1000;
            if patterns.len() >= MAX_PATTERNS {
                // Remove oldest 10% when limit reached
                let to_remove = MAX_PATTERNS / 10;
                patterns.drain(0..to_remove);
            }
            patterns.push(iats);
        }
        
        has_pattern
    }

    /// Detect regular pattern in IATs
    fn detect_regular_pattern(&self, iats: &[Duration]) -> bool {
        if iats.len() < 4 {
            return false;
        }

        // Check for alternating pattern (on/off watermark)
        let threshold = Duration::from_millis(50);
        let alternating = iats.windows(2).all(|w| {
            let diff = if w[0] > w[1] {
                w[0] - w[1]
            } else {
                w[1] - w[0]
            };
            diff > threshold
        });

        // Check for periodic pattern
        let mean_iat: f64 = iats.iter()
            .map(|d| d.as_secs_f64())
            .sum::<f64>() / iats.len() as f64;
        
        let variance: f64 = iats.iter()
            .map(|d| {
                let diff = d.as_secs_f64() - mean_iat;
                diff * diff
            })
            .sum::<f64>() / iats.len() as f64;
        
        let periodic = variance < 0.001; // Low variance indicates periodicity

        alternating || periodic
    }

    /// Mitigate detected watermark
    pub async fn mitigate_watermark(&self, cells: Vec<Cell>) -> Vec<Cell> {
        // Add random delays to break watermark pattern
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();
        
        for cell in cells {
            // Random delay up to 100ms
            let delay = Duration::from_millis(rng.gen_range(0..100));
            tokio::time::sleep(delay).await;
            output.push(cell);
        }
        
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_skew_protection() {
        let mut protection = ClockSkewProtection::new();
        let t1 = protection.now();
        let t2 = protection.now();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_watermark_detection() {
        let detector = WatermarkDetector::new(10);

        // Create alternating pattern (watermark)
        let base = Instant::now();
        let timestamps: Vec<Instant> = (0..10)
            .map(|i| base + Duration::from_millis(if i % 2 == 0 { 100 } else { 10 }))
            .collect();

        // Should detect pattern
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detected = rt.block_on(detector.analyze_pattern(timestamps));
        assert!(detected);
    }

    #[test]
    fn test_add_gaussian_noise_within_reasonable_bounds() {
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            super::super::AntiSurveillanceConfig::default(),
        ));
        let shield = TimingShield::new(config);

        let base = Instant::now();
        let std_dev_ms = 50.0;

        // Run many samples and verify they stay within 5-sigma (extremely unlikely to fail legitimately)
        for _ in 0..50 {
            let noisy = shield.add_gaussian_noise(base, std_dev_ms).unwrap();
            let diff_ms = if noisy >= base {
                noisy.duration_since(base).as_millis()
            } else {
                base.duration_since(noisy).as_millis()
            };
            assert!(diff_ms < 500,
                "Gaussian noise sample {} ms is unexpectedly far from base (>500 ms at 5σ)",
                diff_ms);
        }
    }

    #[test]
    fn test_add_gaussian_noise_zero_std_dev() {
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            super::super::AntiSurveillanceConfig::default(),
        ));
        let shield = TimingShield::new(config);

        let base = Instant::now();
        // std_dev = 0 → noise is always 0 ms, result must equal base
        let result = shield.add_gaussian_noise(base, 0.0);
        assert!(result.is_ok(), "zero std_dev should not error");
        // With 0 std dev the noise drawn is 0, so result should be base or very close
        let noisy = result.unwrap();
        let diff = if noisy >= base {
            noisy.duration_since(base)
        } else {
            base.duration_since(noisy)
        };
        assert!(diff <= Duration::from_millis(1),
            "zero std_dev noise must produce no shift");
    }

    #[tokio::test]
    async fn test_batch_cells_exact_batch_size_boundary() {
        use crate::anti_surveillance::{AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand};
        let mut config = AntiSurveillanceConfig::default();
        config.batch_size = 3;
        config.level = SecurityLevel::Maximum;
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(config));
        let shield = TimingShield::new(config);

        // Exactly batch_size cells — must form a complete batch and be returned
        let cells: Vec<Cell> = (0..3)
            .map(|i| Cell {
                circuit_id: i,
                stream_id: 0,
                command: CellCommand::Data,
                payload: vec![0u8; 10],
                timestamp: Instant::now(),
            })
            .collect();

        let output = shield.protect_timing(cells).await.unwrap();
        // All 3 cells must come out (no loss)
        let data_count = output.iter().filter(|c| c.command == CellCommand::Data).count();
        assert_eq!(data_count, 3,
            "all {} data cells must survive exactly-batch-size protection", 3);
    }

    #[test]
    fn test_clock_skew_tcp_timestamp_wraps_safely() {
        let mut protection = ClockSkewProtection::new();
        // Force a negative offset (simulates subtraction scenario)
        protection.offset_ms = -50;
        // Should not panic even on very short system uptime
        let _ts = protection.tcp_timestamp();
    }

    #[tokio::test]
    async fn test_watermark_detection_below_window_size_returns_false() {
        let detector = WatermarkDetector::new(10);

        // Fewer timestamps than window_size — must return false, not panic
        let base = Instant::now();
        let timestamps: Vec<Instant> = (0..5)
            .map(|i| base + Duration::from_millis(i * 10))
            .collect();

        let detected = detector.analyze_pattern(timestamps).await;
        assert!(!detected,
            "insufficient timestamps (fewer than window_size) must not detect a pattern");
    }
}
