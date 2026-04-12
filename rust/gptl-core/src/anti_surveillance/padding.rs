//! Adaptive Padding Module
//!
//! Implements WTF-PAD (Website Traffic Fingerprinting Protection with Adaptive Defense)
//! and related padding defenses against website fingerprinting attacks.

use super::{AntiSurveillanceConfig, AntiSurveillanceError, Cell, CellCommand};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rand::Rng;
use rand_distr::{Distribution, Exp};

/// Adaptive padding engine
pub struct PaddingEngine {
    config: Arc<RwLock<AntiSurveillanceConfig>>,
    /// State machines for each circuit
    state_machines: Arc<RwLock<Vec<PaddingStateMachine>>>,
    /// Histogram of inter-arrival times
    iat_histogram: Arc<RwLock<Vec<f64>>>,
}

/// Padding state machine (similar to WTF-PAD)
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PaddingStateMachine {
    circuit_id: u32,
    /// Current state
    state: PaddingState,
    /// Last event time
    last_event: Instant,
    /// Scheduled padding timer
    next_padding: Option<Instant>,
    /// Burst counter
    burst_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum PaddingState {
    /// Waiting for burst to start
    Idle,
    /// Within a burst
    Burst,
    /// Gap between bursts
    Gap,
}

impl PaddingEngine {
    /// Create new padding engine
    pub fn new(config: Arc<RwLock<AntiSurveillanceConfig>>) -> Self {
        let state_machines = Arc::new(RwLock::new(Vec::new()));
        
        // Initialize IAT histogram with typical web browsing patterns
        let iat_histogram = vec![
            0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0,
        ];
        
        Self {
            config,
            state_machines,
            iat_histogram: Arc::new(RwLock::new(iat_histogram)),
        }
    }

    /// Initialize the padding engine
    pub async fn initialize(&self) -> Result<(), AntiSurveillanceError> {
        Ok(())
    }

    /// Register a new circuit
    pub async fn register_circuit(&self, circuit_id: u32) {
        let mut machines = self.state_machines.write().await;

        // Prevent unbounded growth - limit to 10,000 circuits
        const MAX_CIRCUITS: usize = 10_000;
        if machines.len() >= MAX_CIRCUITS {
            // Remove oldest 10% when limit reached
            machines.drain(0..MAX_CIRCUITS / 10);
        }

        machines.push(PaddingStateMachine {
            circuit_id,
            state: PaddingState::Idle,
            last_event: Instant::now(),
            next_padding: None,
            burst_count: 0,
        });
    }

    /// Pad cells using adaptive algorithm
    pub async fn pad_cells(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        if cells.is_empty() {
            // Generate pure padding if no real cells
            return Ok(vec![self.generate_padding_cell(0)]);
        }

        let config = self.config.read().await;
        let mut output = Vec::new();

        match config.level {
            super::SecurityLevel::Standard => {
                // Simple padding: add some dummy cells
                let mut rng = rand::thread_rng();
                for cell in cells {
                    output.push(cell);
                    // Randomly add padding
                    if rng.gen::<f64>() < 0.1 {
                        output.push(self.generate_padding_cell(0));
                    }
                }
            }
            super::SecurityLevel::Enhanced => {
                // WTF-PAD style adaptive padding
                output = self.adaptive_pad(cells).await?;
            }
            super::SecurityLevel::Maximum => {
                // Aggressive padding with burst morphing
                output = self.aggressive_pad(cells).await?;
            }
        }

        Ok(output)
    }

    /// Adaptive padding algorithm (WTF-PAD style)
    async fn adaptive_pad(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();
        let histogram = self.iat_histogram.read().await;

        // Group cells by time windows
        let windows = self.group_into_windows(cells, Duration::from_millis(100));

        for window in windows {
            let window_size = window.len();
            
            // Sample target window size from histogram
            let target_size = if let Ok(exp) = Exp::new(0.5) {
                let sample: f64 = exp.sample(&mut rng);
                (sample * 10.0).clamp(5.0, 50.0) as usize
            } else {
                20
            };

            // Add real cells
            output.extend(window);

            // Add padding to reach target
            let padding_needed = target_size.saturating_sub(window_size);
            for _ in 0..padding_needed {
                output.push(self.generate_padding_cell(0));
            }

            // Add inter-burst padding with sampled gap
            if let Some(&gap) = histogram.choose(&mut rng) {
                let gap_duration = Duration::from_secs_f64(gap);
                tokio::time::sleep(gap_duration).await;
            }
        }

        Ok(output)
    }

    /// Aggressive padding for maximum security
    async fn aggressive_pad(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();

        // Fixed burst sizes (defense against website fingerprinting)
        const BURST_SIZES: [usize; 3] = [10, 25, 50];

        // Process cells in fixed-size bursts
        let mut cell_iter = cells.into_iter().peekable();

        while cell_iter.peek().is_some() {
            // Choose random burst size
            let burst_size = BURST_SIZES[rng.gen_range(0..BURST_SIZES.len())];
            
            // Collect cells for this burst
            let mut burst = Vec::new();
            for _ in 0..burst_size {
                if let Some(cell) = cell_iter.next() {
                    burst.push(cell);
                }
            }

            // Pad to burst size
            while burst.len() < burst_size {
                burst.push(self.generate_padding_cell(0));
            }

            // Add random inter-cell timing
            for cell in burst {
                let jitter = Duration::from_millis(rng.gen_range(0..50));
                tokio::time::sleep(jitter).await;
                output.push(cell);
            }

            // Inter-burst gap
            let gap = Duration::from_millis(rng.gen_range(50..200));
            tokio::time::sleep(gap).await;
        }

        Ok(output)
    }

    /// Group cells into time windows
    fn group_into_windows(&self, cells: Vec<Cell>, window_size: Duration) -> Vec<Vec<Cell>> {
        if cells.is_empty() {
            return Vec::new();
        }

        let mut windows: Vec<Vec<Cell>> = Vec::new();
        let mut current_window = Vec::new();
        let window_start = cells[0].timestamp;

        for cell in cells {
            // Use checked_duration_since to avoid panic
            let elapsed = cell.timestamp.saturating_duration_since(window_start);

            if elapsed > window_size && !current_window.is_empty() {
                windows.push(current_window);
                current_window = Vec::new();
            }
            current_window.push(cell);
        }

        if !current_window.is_empty() {
            windows.push(current_window);
        }

        windows
    }

    /// Generate a padding cell
    fn generate_padding_cell(&self, circuit_id: u32) -> Cell {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 509];
        rng.fill(&mut payload[..]);

        Cell {
            circuit_id,
            stream_id: 0,
            command: CellCommand::Padding,
            payload,
            timestamp: Instant::now(),
        }
    }

    /// Update IAT histogram based on observed traffic
    pub async fn update_histogram(&self, iat: f64) {
        let mut histogram = self.iat_histogram.write().await;
        
        // Add new observation with exponential weighting
        histogram.push(iat);
        if histogram.len() > 100 {
            histogram.remove(0);
        }
    }
}

/// Helper trait for choosing random elements
pub trait ChooseRandom<T> {
    fn choose<R: Rng>(&self, rng: &mut R) -> Option<&T>;
}

impl<T> ChooseRandom<T> for Vec<T> {
    fn choose<R: Rng>(&self, rng: &mut R) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            Some(&self[rng.gen_range(0..self.len())])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anti_surveillance::{SecurityLevel, AntiSurveillanceConfig};

    fn create_test_cell(circuit_id: u32, stream_id: u16, command: CellCommand) -> Cell {
        Cell {
            circuit_id,
            stream_id,
            command,
            payload: vec![0u8; 509],
            timestamp: Instant::now(),
        }
    }

    #[tokio::test]
    async fn test_padding_engine_initialization() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);
        assert!(engine.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_register_circuit() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        engine.register_circuit(1).await;
        engine.register_circuit(2).await;

        let machines = engine.state_machines.read().await;
        assert_eq!(machines.len(), 2);
        assert_eq!(machines[0].circuit_id, 1);
        assert_eq!(machines[1].circuit_id, 2);
    }

    #[tokio::test]
    async fn test_circuit_limit() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        // Register more than MAX_CIRCUITS
        for i in 0..10_100 {
            engine.register_circuit(i).await;
        }

        let machines = engine.state_machines.read().await;
        assert!(machines.len() <= 10_000);
    }

    #[tokio::test]
    async fn test_pad_cells_empty() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let result = engine.pad_cells(vec![]).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].command, CellCommand::Padding);
    }

    #[tokio::test]
    async fn test_standard_padding() {
        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Standard;
        let config = Arc::new(RwLock::new(config));
        let engine = PaddingEngine::new(config);

        let cells = vec![
            create_test_cell(1, 1, CellCommand::Data),
            create_test_cell(1, 1, CellCommand::Data),
        ];

        let result = engine.pad_cells(cells).await.unwrap();
        // Should have at least the original cells
        assert!(result.len() >= 2);
    }

    #[tokio::test]
    async fn test_enhanced_padding() {
        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Enhanced;
        let config = Arc::new(RwLock::new(config));
        let engine = PaddingEngine::new(config);

        let cells = vec![
            create_test_cell(1, 1, CellCommand::Data),
            create_test_cell(1, 1, CellCommand::Data),
        ];

        let result = engine.pad_cells(cells).await.unwrap();
        // Enhanced padding should add more cells
        assert!(result.len() >= 2);
    }

    #[tokio::test]
    async fn test_maximum_padding() {
        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Maximum;
        let config = Arc::new(RwLock::new(config));
        let engine = PaddingEngine::new(config);

        let cells = vec![
            create_test_cell(1, 1, CellCommand::Data),
        ];

        let result = engine.pad_cells(cells).await.unwrap();
        // Maximum padding should pad to burst size (at least 10)
        assert!(result.len() >= 10);
    }

    #[tokio::test]
    async fn test_group_into_windows() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let cells = vec![
            create_test_cell(1, 1, CellCommand::Data),
            create_test_cell(1, 1, CellCommand::Data),
        ];

        let windows = engine.group_into_windows(cells, Duration::from_millis(100));
        assert!(!windows.is_empty());
    }

    #[tokio::test]
    async fn test_group_into_windows_empty() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let windows = engine.group_into_windows(vec![], Duration::from_millis(100));
        assert!(windows.is_empty());
    }

    #[tokio::test]
    async fn test_generate_padding_cell() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let cell = engine.generate_padding_cell(42);
        assert_eq!(cell.circuit_id, 42);
        assert_eq!(cell.command, CellCommand::Padding);
        assert_eq!(cell.payload.len(), 509);
    }

    #[tokio::test]
    async fn test_update_histogram() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let initial_len = engine.iat_histogram.read().await.len();

        engine.update_histogram(0.05).await;

        let new_len = engine.iat_histogram.read().await.len();
        assert_eq!(new_len, initial_len + 1);
    }

    #[tokio::test]
    async fn test_histogram_bounded() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        // Add many observations
        for i in 0..150 {
            engine.update_histogram(i as f64 * 0.01).await;
        }

        let len = engine.iat_histogram.read().await.len();
        assert!(len <= 100);
    }

    #[test]
    fn test_choose_random() {
        let vec = vec![1, 2, 3, 4, 5];
        let mut rng = rand::thread_rng();

        let choice = vec.choose(&mut rng);
        assert!(choice.is_some());
        assert!(vec.contains(choice.unwrap()));
    }

    #[test]
    fn test_choose_random_empty() {
        let vec: Vec<i32> = vec![];
        let mut rng = rand::thread_rng();

        let choice = vec.choose(&mut rng);
        assert!(choice.is_none());
    }

    #[tokio::test]
    async fn test_padding_preserves_order() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let cells = vec![
            create_test_cell(1, 1, CellCommand::Data),
            create_test_cell(1, 2, CellCommand::Data),
            create_test_cell(1, 3, CellCommand::Data),
        ];

        let result = engine.pad_cells(cells).await.unwrap();

        // Find data cells and verify order
        let data_cells: Vec<_> = result.iter()
            .filter(|c| c.command == CellCommand::Data)
            .collect();

        assert_eq!(data_cells.len(), 3);
        assert_eq!(data_cells[0].stream_id, 1);
        assert_eq!(data_cells[1].stream_id, 2);
        assert_eq!(data_cells[2].stream_id, 3);
    }

    #[tokio::test]
    async fn test_padding_randomness() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let cell1 = engine.generate_padding_cell(1);
        let cell2 = engine.generate_padding_cell(1);

        // Payloads should be different (random)
        assert_ne!(cell1.payload, cell2.payload);
    }

    #[test]
    fn test_padding_cell_payload_not_all_zeros() {
        // Security requirement: padding cells must use random non-zero payloads
        // so they are indistinguishable from real data.
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        // Generate several cells and verify none are all-zero.
        for i in 0..10 {
            let cell = engine.generate_padding_cell(i);
            assert_eq!(cell.payload.len(), 509, "padding cell payload length must be 509 bytes");
            let all_zero = cell.payload.iter().all(|&b| b == 0);
            assert!(!all_zero,
                "padding cell payload must not be all-zeros (security requirement)");
        }
    }

    #[tokio::test]
    async fn test_padding_engine_empty_input_generates_one_padding_cell() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        let result = engine.pad_cells(vec![]).await.unwrap();
        assert_eq!(result.len(), 1, "empty input must produce exactly one padding cell");
        assert_eq!(result[0].command, CellCommand::Padding);
        // The single cell's payload must not be all-zero
        let all_zero = result[0].payload.iter().all(|&b| b == 0);
        assert!(!all_zero,
            "the generated padding cell payload must not be all-zeros");
    }

    #[tokio::test]
    async fn test_histogram_bounds_after_many_updates() {
        // Verifies the ring-buffer-style histogram stays bounded at 100 entries
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        for i in 0..200 {
            engine.update_histogram(i as f64 * 0.001).await;
        }

        let len = engine.iat_histogram.read().await.len();
        assert!(len <= 100, "histogram must not exceed 100 entries, got {}", len);
    }

    #[tokio::test]
    async fn test_circuit_registration_bounded_growth() {
        let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
        let engine = PaddingEngine::new(config);

        // Register more than the 10_000 circuit limit
        for i in 0_u32..10_200 {
            engine.register_circuit(i).await;
        }

        let machines = engine.state_machines.read().await;
        assert!(machines.len() <= 10_000,
            "circuit registration must not exceed 10,000 entries, got {}", machines.len());
    }
}

