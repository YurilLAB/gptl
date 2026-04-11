//! Traffic Shaping Module
//! 
//! Implements countermeasures against traffic confirmation attacks (Murdoch-Danezis)
//! and website fingerprinting by shaping traffic to constant-rate patterns.

use super::{AntiSurveillanceConfig, AntiSurveillanceError, Cell, CellCommand};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Interval};

/// Traffic shaper that enforces constant-rate transmission
pub struct TrafficShaper {
    config: Arc<RwLock<AntiSurveillanceConfig>>,
    cell_queue: Arc<RwLock<VecDeque<Cell>>>,
    padding_queue: Arc<RwLock<VecDeque<Cell>>>,
    transmission_interval: Arc<RwLock<Interval>>,
}

impl TrafficShaper {
    /// Create a new traffic shaper
    pub fn new(config: Arc<RwLock<AntiSurveillanceConfig>>) -> Self {
        let cell_queue = Arc::new(RwLock::new(VecDeque::new()));
        let padding_queue = Arc::new(RwLock::new(VecDeque::new()));
        
        // Default 100 cells/second = 10ms interval
        let transmission_interval = Arc::new(RwLock::new(interval(Duration::from_millis(10))));
        
        Self {
            config,
            cell_queue,
            padding_queue,
            transmission_interval,
        }
    }

    /// Initialize the traffic shaper
    pub async fn initialize(&self) -> Result<(), AntiSurveillanceError> {
        let config = self.config.read().await;
        let interval_ms = (1000.0 / config.target_rate) as u64;
        
        let mut tx_interval = self.transmission_interval.write().await;
        *tx_interval = interval(Duration::from_millis(interval_ms));
        
        Ok(())
    }

    /// Shape cells to constant rate
    pub async fn shape_cells(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut queue = self.cell_queue.write().await;
        
        // Add incoming cells to queue
        for cell in cells {
            queue.push_back(cell);
        }
        
        // Return cells at constant rate
        let config = self.config.read().await;
        let mut output = Vec::new();
        let target_count = (config.target_rate / 10.0) as usize; // Cells per tick
        
        // Take real cells first, then padding
        for _ in 0..target_count {
            if let Some(cell) = queue.pop_front() {
                output.push(cell);
            } else {
                // Generate padding cell
                output.push(self.generate_padding_cell());
            }
        }
        
        Ok(output)
    }

    /// Generate a padding cell
    fn generate_padding_cell(&self) -> Cell {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 509];
        rng.fill(&mut payload[..]);

        Cell {
            circuit_id: 0, // Special circuit for padding
            stream_id: 0,
            command: CellCommand::Padding,
            payload,
            timestamp: Instant::now(),
        }
    }

    /// Schedule cell for transmission
    pub async fn schedule_cell(&self, cell: Cell) -> Result<(), AntiSurveillanceError> {
        let mut queue = self.cell_queue.write().await;
        queue.push_back(cell);
        Ok(())
    }

    /// Get next cell for transmission (blocking)
    pub async fn next_cell(&self) -> Option<Cell> {
        let mut interval = self.transmission_interval.write().await;
        interval.tick().await;
        
        let mut queue = self.cell_queue.write().await;
        queue.pop_front()
    }
}

/// Burst morphing - reshape traffic bursts to standard patterns
/// Defends against website fingerprinting
pub struct BurstMorphing {
    /// Target burst patterns (length, interval)
    target_patterns: Vec<(usize, Duration)>,
    /// Current burst buffer
    burst_buffer: VecDeque<Cell>,
    /// Last burst time
    last_burst: Instant,
}

impl BurstMorphing {
    /// Create new burst morphing with standard patterns
    pub fn new() -> Self {
        // Standard burst patterns that mimic common websites
        let target_patterns = vec![
            (10, Duration::from_millis(50)),   // Small burst
            (25, Duration::from_millis(100)),  // Medium burst  
            (50, Duration::from_millis(200)),  // Large burst
        ];
        
        Self {
            target_patterns,
            burst_buffer: VecDeque::new(),
            last_burst: Instant::now(),
        }
    }

    /// Morph a burst of cells to standard pattern
    pub fn morph_burst(&mut self, cells: Vec<Cell>) -> Vec<Cell> {
        self.burst_buffer.extend(cells);
        
        // Find best matching pattern
        let buffer_len = self.burst_buffer.len();
        let default_pattern = (10, Duration::from_millis(50));
        let target_pattern = self.target_patterns
            .iter()
            .min_by_key(|(size, _)| {
                (*size as isize - buffer_len as isize).abs()
            })
            .unwrap_or(&default_pattern);
        
        // Build output burst
        let mut output = Vec::new();
        let target_size = target_pattern.0;
        
        // Take cells from buffer
        for _ in 0..target_size.min(buffer_len) {
            if let Some(cell) = self.burst_buffer.pop_front() {
                output.push(cell);
            }
        }
        
        // Pad if necessary
        while output.len() < target_size {
            output.push(self.generate_padding_cell());
        }
        
        self.last_burst = Instant::now();
        output
    }

    /// Generate padding cell
    fn generate_padding_cell(&self) -> Cell {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut payload = vec![0u8; 509];
        rng.fill(&mut payload[..]);

        Cell {
            circuit_id: 0,
            stream_id: 0,
            command: CellCommand::Padding,
            payload,
            timestamp: Instant::now(),
        }
    }
}

/// Traffic splitting for multi-path routing
/// Defends against traffic confirmation by splitting across paths
pub struct TrafficSplitter {
    /// Number of paths to split across
    num_paths: usize,
    /// Split ratio (using secret sharing)
    split_ratio: f64,
}

impl TrafficSplitter {
    /// Create new traffic splitter
    pub fn new(num_paths: usize) -> Self {
        Self {
            num_paths,
            split_ratio: 1.0 / num_paths as f64,
        }
    }

    /// Split cells across multiple paths
    pub fn split_cells(&self, cells: Vec<Cell>) -> Vec<Vec<Cell>> {
        let mut paths: Vec<Vec<Cell>> = vec![Vec::new(); self.num_paths];

        for (i, cell) in cells.into_iter().enumerate() {
            let path_idx = i % self.num_paths;
            paths[path_idx].push(cell);
        }

        // Ensure all paths have same length (padding)
        let max_len = paths.iter().map(|p| p.len()).max().unwrap_or(0);
        for path in &mut paths {
            while path.len() < max_len {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let mut payload = vec![0u8; 509];
                rng.fill(&mut payload[..]);

                path.push(Cell {
                    circuit_id: 0,
                    stream_id: 0,
                    command: CellCommand::Padding,
                    payload,
                    timestamp: Instant::now(),
                });
            }
        }

        paths
    }

    /// Reassemble cells from multiple paths
    pub fn reassemble_cells(&self, paths: Vec<Vec<Cell>>) -> Vec<Cell> {
        let mut output = Vec::new();
        let max_len = paths.iter().map(|p| p.len()).max().unwrap_or(0);
        
        for i in 0..max_len {
            for path in &paths {
                if let Some(cell) = path.get(i) {
                    if cell.command != CellCommand::Padding {
                        output.push(cell.clone());
                    }
                }
            }
        }
        
        output
    }
}

/// Cover traffic generator
/// Generates background noise during idle periods
pub struct CoverTrafficGenerator {
    /// Cover traffic rate (cells/second)
    rate: f64,
    /// Running state
    running: Arc<RwLock<bool>>,
}

impl CoverTrafficGenerator {
    /// Create new cover traffic generator
    pub fn new(rate: f64) -> Self {
        Self {
            rate,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start generating cover traffic
    pub async fn start(&self) -> mpsc::Receiver<Cell> {
        let (tx, rx) = mpsc::channel(1000);
        let running = self.running.clone();
        let interval_ms = (1000.0 / self.rate) as u64;

        // Set running to true
        *running.write().await = true;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(interval_ms));

            loop {
                ticker.tick().await;

                if !*running.read().await {
                    break;
                }

                // Generate random payload for each cell
                use rand::RngCore;
                let mut payload = vec![0u8; 509];
                rand::rngs::OsRng.fill_bytes(&mut payload);

                let cell = Cell {
                    circuit_id: 0,
                    stream_id: 0,
                    command: CellCommand::Padding,
                    payload,
                    timestamp: Instant::now(),
                };

                if tx.send(cell).await.is_err() {
                    break;
                }
            }
        });

        rx
    }

    /// Stop generating cover traffic
    pub async fn stop(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_splitter() {
        let splitter = TrafficSplitter::new(3);
        
        let cells = vec![
            Cell { circuit_id: 1, stream_id: 1, command: CellCommand::Data, payload: vec![1], timestamp: Instant::now() },
            Cell { circuit_id: 1, stream_id: 1, command: CellCommand::Data, payload: vec![2], timestamp: Instant::now() },
            Cell { circuit_id: 1, stream_id: 1, command: CellCommand::Data, payload: vec![3], timestamp: Instant::now() },
        ];
        
        let paths = splitter.split_cells(cells);
        assert_eq!(paths.len(), 3);
        
        // All paths should have same length (padded)
        assert_eq!(paths[0].len(), paths[1].len());
        assert_eq!(paths[1].len(), paths[2].len());
    }
}
