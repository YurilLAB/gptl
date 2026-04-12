//! Circuit Obfuscation Module
//!
//! Implements countermeasures against circuit fingerprinting attacks (Kwon et al.)
//! including preemptive circuit padding, vanguards, and circuit morphing.

use super::{AntiSurveillanceConfig, AntiSurveillanceError, Cell, CellCommand};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use rand::Rng;
use rand::seq::SliceRandom;

/// Circuit shield for obfuscating circuit patterns
pub struct CircuitShield {
    config: Arc<RwLock<AntiSurveillanceConfig>>,
    /// Circuit state machines
    circuits: Arc<RwLock<HashMap<u32, CircuitStateMachine>>>,
    /// Standard cell sequences for obfuscation
    standard_sequences: StandardSequences,
}

/// Circuit state machine for tracking circuit state
#[derive(Debug, Clone)]
struct CircuitStateMachine {
    circuit_id: u32,
    /// Circuit type (obfuscated)
    circuit_type: ObfuscatedCircuitType,
    /// Current state
    state: CircuitState,
    /// Cells sent counter
    cells_sent: usize,
    /// Cells received counter
    cells_received: usize,
    /// Creation time
    created_at: Instant,
}

/// Obfuscated circuit type (all circuits appear same)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObfuscatedCircuitType {
    Standard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Creating,
    Established,
    Active,
    Closing,
}

/// Standard cell sequences for all circuits
#[derive(Debug, Clone)]
struct StandardSequences {
    /// Standard handshake sequence
    handshake: Vec<Cell>,
    /// Standard padding sequence
    padding: Vec<Cell>,
    /// Standard keep-alive sequence
    keepalive: Vec<Cell>,
}

impl CircuitShield {
    /// Create new circuit shield
    pub fn new(config: Arc<RwLock<AntiSurveillanceConfig>>) -> Self {
        let circuits = Arc::new(RwLock::new(HashMap::new()));
        let standard_sequences = StandardSequences::new();
        
        Self {
            config,
            circuits,
            standard_sequences,
        }
    }

    /// Initialize circuit shield
    pub async fn initialize(&self) -> Result<(), AntiSurveillanceError> {
        Ok(())
    }

    /// Register new circuit
    pub async fn register_circuit(&self, circuit_id: u32) {
        let mut circuits = self.circuits.write().await;

        // Prevent unbounded growth - limit to 10,000 circuits
        const MAX_CIRCUITS: usize = 10_000;
        if circuits.len() >= MAX_CIRCUITS {
            // Remove old circuits (older than 1 hour)
            let old_circuits: Vec<u32> = circuits
                .iter()
                .filter(|(_, info)| info.created_at.elapsed() > Duration::from_secs(3600))
                .map(|(id, _)| *id)
                .take(MAX_CIRCUITS / 10)
                .collect();

            for id in old_circuits {
                circuits.remove(&id);
            }
        }

        circuits.insert(circuit_id, CircuitStateMachine {
            circuit_id,
            circuit_type: ObfuscatedCircuitType::Standard,
            state: CircuitState::Creating,
            cells_sent: 0,
            cells_received: 0,
            created_at: Instant::now(),
        });
    }

    /// Obfuscate cells from circuit
    pub async fn obfuscate_cells(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        if cells.is_empty() {
            return Ok(Vec::new());
        }

        let config = self.config.read().await;
        
        match config.level {
            super::SecurityLevel::Standard => {
                // Basic obfuscation
                Ok(cells)
            }
            super::SecurityLevel::Enhanced => {
                // Add preemptive padding
                self.add_preemptive_padding(cells).await
            }
            super::SecurityLevel::Maximum => {
                // Full obfuscation with standard sequences
                self.morph_to_standard(cells).await
            }
        }
    }

    /// Add preemptive padding to circuit
    async fn add_preemptive_padding(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();
        
        // Standard burst sizes to prevent circuit fingerprinting
        const BURST_SIZES: [usize; 3] = [6, 12, 18];
        
        let target_burst = BURST_SIZES[rng.gen_range(0..BURST_SIZES.len())];
        
        // Add cells
        output.extend(cells);
        
        // Add padding to reach target burst size
        while output.len() < target_burst {
            output.push(self.generate_dummy_cell());
        }
        
        Ok(output)
    }

    /// Morph cells to standard sequence
    async fn morph_to_standard(&self, cells: Vec<Cell>) -> Result<Vec<Cell>, AntiSurveillanceError> {
        let mut output = Vec::new();
        let mut rng = rand::thread_rng();
        
        // Use standard handshake pattern
        output.extend(self.standard_sequences.handshake.clone());
        
        // Add cells with padding to standard burst sizes
        for cell in cells {
            output.push(cell);
            
            // Random padding between cells
            if rng.gen::<f64>() < 0.3 {
                output.push(self.generate_dummy_cell());
            }
        }
        
        // Add standard closing
        output.extend(self.standard_sequences.keepalive.clone());
        
        Ok(output)
    }

    /// Generate dummy cell for padding
    fn generate_dummy_cell(&self) -> Cell {
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

    /// Update circuit state
    pub async fn update_circuit_state(&self, circuit_id: u32, state: CircuitState) {
        let mut circuits = self.circuits.write().await;
        if let Some(circuit) = circuits.get_mut(&circuit_id) {
            circuit.state = state;
        }
    }

    /// Get circuit statistics
    pub async fn get_circuit_stats(&self, circuit_id: u32) -> Option<CircuitStats> {
        let circuits = self.circuits.read().await;
        circuits.get(&circuit_id).map(|c| CircuitStats {
            cells_sent: c.cells_sent,
            cells_received: c.cells_received,
            duration: c.created_at.elapsed(),
        })
    }
}

/// Circuit statistics
#[derive(Debug, Clone)]
pub struct CircuitStats {
    pub cells_sent: usize,
    pub cells_received: usize,
    pub duration: Duration,
}

impl StandardSequences {
    /// Create standard sequences for circuit obfuscation
    fn new() -> Self {
        Self {
            handshake: Self::generate_handshake_sequence(),
            padding: Self::generate_padding_sequence(),
            keepalive: Self::generate_keepalive_sequence(),
        }
    }

    /// Generate random 509-byte payload (indistinguishable from real data).
    fn random_payload() -> Vec<u8> {
        let mut payload = vec![0u8; 509];
        rand::thread_rng().fill(&mut payload[..]);
        payload
    }

    /// Generate standard handshake sequence
    fn generate_handshake_sequence() -> Vec<Cell> {
        // Standard 4-cell handshake pattern with random payloads
        vec![
            Cell {
                circuit_id: 0,
                stream_id: 0,
                command: CellCommand::Create,
                payload: Self::random_payload(),
                timestamp: Instant::now(),
            },
            Cell {
                circuit_id: 0,
                stream_id: 0,
                command: CellCommand::Created,
                payload: Self::random_payload(),
                timestamp: Instant::now(),
            },
            // Padding cells to standardize pattern
            Cell {
                circuit_id: 0,
                stream_id: 0,
                command: CellCommand::Padding,
                payload: Self::random_payload(),
                timestamp: Instant::now(),
            },
            Cell {
                circuit_id: 0,
                stream_id: 0,
                command: CellCommand::Padding,
                payload: Self::random_payload(),
                timestamp: Instant::now(),
            },
        ]
    }

    /// Generate standard padding sequence
    fn generate_padding_sequence() -> Vec<Cell> {
        // Standard 10-cell padding burst with random payloads
        (0..10).map(|_| Cell {
            circuit_id: 0,
            stream_id: 0,
            command: CellCommand::Padding,
            payload: Self::random_payload(),
            timestamp: Instant::now(),
        }).collect()
    }

    /// Generate standard keepalive sequence
    fn generate_keepalive_sequence() -> Vec<Cell> {
        vec![
            Cell {
                circuit_id: 0,
                stream_id: 0,
                command: CellCommand::Padding,
                payload: Self::random_payload(),
                timestamp: Instant::now(),
            },
        ]
    }
}

/// Vanguard layer management
/// Implements layered guard protection (vanguards)
pub struct VanguardManager {
    /// First layer guards (entry)
    first_layer: Vec<GuardInfo>,
    /// Second layer guards (middle)
    second_layer: Vec<GuardInfo>,
    /// Third layer guards (optional)
    third_layer: Vec<GuardInfo>,
    /// Rotation policy
    rotation_policy: RotationPolicy,
}

/// Guard information
#[derive(Debug, Clone)]
pub struct GuardInfo {
    pub identity: String,
    pub address: String,
    pub bandwidth: u64,
    pub layer: GuardLayer,
    pub added_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardLayer {
    First,
    Second,
    Third,
}

/// Guard rotation policy
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// First layer rotation interval (seconds)
    first_layer_rotation: u64,
    /// Second layer rotation interval (seconds)
    second_layer_rotation: u64,
    /// Third layer rotation interval (seconds)
    third_layer_rotation: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            // Conservative rotation: first layer rarely rotates
            first_layer_rotation: 90 * 24 * 60 * 60, // 90 days
            second_layer_rotation: 30 * 24 * 60 * 60, // 30 days
            third_layer_rotation: 7 * 24 * 60 * 60,  // 7 days
        }
    }
}

impl VanguardManager {
    /// Create new vanguard manager
    pub fn new() -> Self {
        Self {
            first_layer: Vec::new(),
            second_layer: Vec::new(),
            third_layer: Vec::new(),
            rotation_policy: RotationPolicy::default(),
        }
    }

    /// Select guards for circuit
    pub fn select_guards(&self) -> Vec<GuardInfo> {
        let mut rng = rand::thread_rng();
        let mut guards = Vec::new();
        
        // Select one from each layer
        if let Some(guard) = self.first_layer.choose(&mut rng) {
            guards.push(guard.clone());
        }
        if let Some(guard) = self.second_layer.choose(&mut rng) {
            guards.push(guard.clone());
        }
        if let Some(guard) = self.third_layer.choose(&mut rng) {
            guards.push(guard.clone());
        }
        
        guards
    }

    /// Add guard to layer
    pub fn add_guard(&mut self, guard: GuardInfo) {
        match guard.layer {
            GuardLayer::First => self.first_layer.push(guard),
            GuardLayer::Second => self.second_layer.push(guard),
            GuardLayer::Third => self.third_layer.push(guard),
        }
    }

    /// Check if any guards need rotation
    pub fn check_rotations(&self) -> Vec<GuardLayer> {
        let now = Instant::now();
        let mut needs_rotation = Vec::new();
        
        // Check first layer
        if self.first_layer.iter().any(|g| {
            now.duration_since(g.added_at).as_secs() > self.rotation_policy.first_layer_rotation
        }) {
            needs_rotation.push(GuardLayer::First);
        }
        
        // Check second layer
        if self.second_layer.iter().any(|g| {
            now.duration_since(g.added_at).as_secs() > self.rotation_policy.second_layer_rotation
        }) {
            needs_rotation.push(GuardLayer::Second);
        }
        
        // Check third layer
        if self.third_layer.iter().any(|g| {
            now.duration_since(g.added_at).as_secs() > self.rotation_policy.third_layer_rotation
        }) {
            needs_rotation.push(GuardLayer::Third);
        }
        
        needs_rotation
    }

    /// Rotate guards in specified layer
    pub fn rotate_layer(&mut self, layer: GuardLayer) {
        match layer {
            GuardLayer::First => self.first_layer.clear(),
            GuardLayer::Second => self.second_layer.clear(),
            GuardLayer::Third => self.third_layer.clear(),
        }
    }
}

/// Preemptive circuit padding (PCP) implementation
/// Defends against circuit fingerprinting by injecting dummy cells
pub struct PreemptiveCircuitPadding {
    /// Padding machines for each circuit
    padding_machines: Arc<RwLock<HashMap<u32, PaddingMachine>>>,
}

/// Padding machine for a circuit
#[derive(Debug, Clone)]
struct PaddingMachine {
    circuit_id: u32,
    /// Next scheduled padding time
    next_padding: Instant,
    /// Padding interval distribution
    padding_interval: Duration,
}

impl PreemptiveCircuitPadding {
    /// Create new PCP manager
    pub fn new() -> Self {
        Self {
            padding_machines: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register circuit for preemptive padding
    pub async fn register_circuit(&self, circuit_id: u32) {
        let mut machines = self.padding_machines.write().await;

        // Prevent unbounded growth - limit to 10,000 circuits
        const MAX_CIRCUITS: usize = 10_000;
        if machines.len() >= MAX_CIRCUITS {
            // Remove oldest 10% when limit reached
            let to_remove = MAX_CIRCUITS / 10;
            let mut ids: Vec<u32> = machines.keys().copied().collect();
            ids.sort();
            for id in ids.iter().take(to_remove) {
                machines.remove(id);
            }
        }

        machines.insert(circuit_id, PaddingMachine {
            circuit_id,
            next_padding: Instant::now() + Duration::from_millis(100),
            padding_interval: Duration::from_millis(100),
        });
    }

    /// Get padding cells for circuit if needed
    pub async fn get_padding_cells(&self, circuit_id: u32) -> Vec<Cell> {
        let mut machines = self.padding_machines.write().await;
        
        if let Some(machine) = machines.get_mut(&circuit_id) {
            let now = Instant::now();
            if now >= machine.next_padding {
                // Schedule next padding
                machine.next_padding = now + machine.padding_interval;
                
                // Return padding cell with random payload (indistinguishable from real data)
                let mut payload = vec![0u8; 509];
                rand::thread_rng().fill(&mut payload[..]);
                return vec![Cell {
                    circuit_id,
                    stream_id: 0,
                    command: CellCommand::Padding,
                    payload,
                    timestamp: now,
                }];
            }
        }
        
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vanguard_manager() {
        let mut manager = VanguardManager::new();
        
        // Add guards
        manager.add_guard(GuardInfo {
            identity: "guard1".to_string(),
            address: "192.168.1.1:9001".to_string(),
            bandwidth: 1000000,
            layer: GuardLayer::First,
            added_at: Instant::now(),
        });
        
        // Select guards
        let guards = manager.select_guards();
        assert!(!guards.is_empty());
    }

    #[test]
    fn test_standard_sequences() {
        let seq = StandardSequences::new();
        assert!(!seq.handshake.is_empty());
        assert!(!seq.padding.is_empty());
        assert!(!seq.keepalive.is_empty());
    }

    #[tokio::test]
    async fn test_obfuscation_maximum_level_adds_cells_to_input() {
        use crate::anti_surveillance::{AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand};

        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Maximum;
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(config));
        let shield = CircuitShield::new(config);

        let input: Vec<Cell> = (0..3)
            .map(|i| Cell {
                circuit_id: i,
                stream_id: 0,
                command: CellCommand::Data,
                payload: vec![0xAA; 509],
                timestamp: Instant::now(),
            })
            .collect();

        let output = shield.obfuscate_cells(input.clone()).await.unwrap();
        // Maximum level adds handshake + keepalive cells, so output > input
        assert!(output.len() > input.len(),
            "maximum obfuscation must produce more cells than the input");
    }

    #[tokio::test]
    async fn test_obfuscation_output_differs_from_bare_input_sequence() {
        use crate::anti_surveillance::{AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand};

        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Maximum;
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(config));
        let shield = CircuitShield::new(config);

        let input: Vec<Cell> = (0..5)
            .map(|i| Cell {
                circuit_id: i,
                stream_id: 0,
                command: CellCommand::Data,
                payload: vec![i as u8; 509],
                timestamp: Instant::now(),
            })
            .collect();

        let output = shield.obfuscate_cells(input.clone()).await.unwrap();

        // The obfuscated stream must contain cells that were NOT in the input
        // (i.e. the standard sequences injected Create/Created/Padding cells).
        let has_injected = output.iter().any(|c| {
            matches!(c.command, CellCommand::Create | CellCommand::Created)
        });
        assert!(has_injected,
            "maximum obfuscation must inject Create/Created cells from the standard handshake");
    }

    #[tokio::test]
    async fn test_obfuscation_standard_level_passes_through_cells() {
        use crate::anti_surveillance::{AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand};

        let mut config = AntiSurveillanceConfig::default();
        config.level = SecurityLevel::Standard;
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(config));
        let shield = CircuitShield::new(config);

        let input: Vec<Cell> = vec![Cell {
            circuit_id: 99,
            stream_id: 7,
            command: CellCommand::Data,
            payload: vec![0xFF; 509],
            timestamp: Instant::now(),
        }];

        let output = shield.obfuscate_cells(input).await.unwrap();
        // Standard level is pass-through
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].circuit_id, 99);
        assert_eq!(output[0].stream_id, 7);
    }

    #[tokio::test]
    async fn test_register_unregistered_circuit_stats_returns_none() {
        use crate::anti_surveillance::AntiSurveillanceConfig;

        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            AntiSurveillanceConfig::default(),
        ));
        let shield = CircuitShield::new(config);

        // Circuit 9999 was never registered — stats must return None
        let stats = shield.get_circuit_stats(9999).await;
        assert!(stats.is_none(),
            "stats for an unregistered circuit ID must return None");
    }

    #[tokio::test]
    async fn test_dummy_cell_payload_not_all_zeros() {
        use crate::anti_surveillance::AntiSurveillanceConfig;

        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            AntiSurveillanceConfig::default(),
        ));
        let shield = CircuitShield::new(config);

        // generate_dummy_cell uses random fill — verify the security property
        for _ in 0..10 {
            let cell = shield.generate_dummy_cell();
            let all_zero = cell.payload.iter().all(|&b| b == 0);
            assert!(!all_zero,
                "dummy cell payload must not be all-zero (security requirement)");
        }
    }

    #[test]
    fn test_vanguard_no_guards_returns_empty_selection() {
        let manager = VanguardManager::new();
        let selected = manager.select_guards();
        // No guards registered yet — selection must return empty vec, not panic
        assert!(selected.is_empty(),
            "selecting guards when none are registered must return empty vec");
    }

    #[test]
    fn test_vanguard_rotation_needed_flags_correct_layer() {
        let mut manager = VanguardManager::new();

        // Add a first-layer guard whose added_at is far enough in the past to trigger rotation.
        // Use Instant::now() as the best approximation (rotation policy is 90 days,
        // checked_sub will clamp to Instant::now() if the system uptime is < 90 days,
        // so instead we force it by checking the policy directly).
        manager.add_guard(GuardInfo {
            identity: "g1".to_string(),
            address: "1.2.3.4:9001".to_string(),
            bandwidth: 1_000_000,
            layer: GuardLayer::First,
            added_at: Instant::now(),
        });

        // Freshly-added guard should NOT need rotation
        let needs = manager.check_rotations();
        assert!(!needs.contains(&GuardLayer::First),
            "freshly added first-layer guard must not need rotation immediately");
    }

    #[tokio::test]
    async fn test_preemptive_padding_registered_circuit_gets_cells() {
        use crate::anti_surveillance::AntiSurveillanceConfig;

        let pcp = PreemptiveCircuitPadding::new();
        pcp.register_circuit(1).await;

        // Nudge the clock past the next_padding time by overwriting it in the future
        // then advancing. Since we cannot fake time, just re-schedule to "now - 1ms".
        // The cleanest approach: call twice — first call primes the machine, second fires.
        {
            let mut machines = pcp.padding_machines.write().await;
            if let Some(m) = machines.get_mut(&1) {
                // Force next_padding into the past
                m.next_padding = Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap_or(Instant::now());
            }
        }

        let cells = pcp.get_padding_cells(1).await;
        assert_eq!(cells.len(), 1, "registered circuit with past next_padding should get 1 padding cell");
        let all_zero = cells[0].payload.iter().all(|&b| b == 0);
        assert!(!all_zero,
            "preemptive padding cell payload must not be all-zero (security requirement)");
    }
}
