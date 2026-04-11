//! Integration tests for gptl-core
//!
//! Tests interactions between anti-surveillance modules, relay selection,
//! and change tracking.

use gptl_core::{
    anti_surveillance::{
        AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand,
        padding::PaddingEngine,
        timing_protection::TimingShield,
        traffic_shaping::TrafficShaper,
        circuit_obfuscation::CircuitShield,
    },
    relay_registry::{InMemoryRegistry, RelayInfo, RelayCriteria, SecurityLevel as RelaySecurityLevel},
    relay_selector::{RelaySelector, SelectionStrategy, SelectorConfig},
    changes::{ChangeTracker, ChangeTrackerConfig, SystemChange, ChangeCategory},
    RelayRegistry,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_anti_surveillance_pipeline() {
    // Create anti-surveillance config
    let mut config = AntiSurveillanceConfig::default();
    config.level = SecurityLevel::Enhanced;
    let config = Arc::new(RwLock::new(config));

    // Initialize modules
    let padding_engine = PaddingEngine::new(config.clone());
    let timing_shield = TimingShield::new(config.clone());
    let traffic_shaper = TrafficShaper::new(config.clone());

    padding_engine.initialize().await.unwrap();
    timing_shield.initialize().await.unwrap();
    traffic_shaper.initialize().await.unwrap();

    // Create test cells
    let cells = vec![
        Cell {
            circuit_id: 1,
            stream_id: 1,
            command: CellCommand::Data,
            payload: vec![0u8; 509],
            timestamp: Instant::now(),
        },
        Cell {
            circuit_id: 1,
            stream_id: 1,
            command: CellCommand::Data,
            payload: vec![1u8; 509],
            timestamp: Instant::now(),
        },
    ];

    // Apply padding
    let padded_cells = padding_engine.pad_cells(cells).await.unwrap();
    assert!(padded_cells.len() >= 2);

    // Apply timing protection
    let timed_cells = timing_shield.protect_timing(padded_cells).await.unwrap();
    assert!(!timed_cells.is_empty());

    // Apply traffic shaping
    let shaped_cells = traffic_shaper.shape_cells(timed_cells).await.unwrap();
    assert!(!shaped_cells.is_empty());
}

#[tokio::test]
async fn test_relay_selection_with_anti_surveillance() {
    // Create registry and add relays
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..10 {
        let relay = RelayInfo::new(
            format!("192.168.1.{}:9001", i + 1),
            format!("key{}", i),
            (i as u64 + 1) * 1_000_000,
        );
        registry.register(relay).await.unwrap();
    }

    // Create selector with enhanced security
    let config = SelectorConfig {
        strategy: SelectionStrategy::Hybrid,
        min_security_level: Some(RelaySecurityLevel::Enhanced),
        ..Default::default()
    };
    let selector = RelaySelector::with_config(registry.clone(), config);

    // Select multiple relays for circuit
    let relays = selector.select_multiple(3, true).await.unwrap();
    assert_eq!(relays.len(), 3);

    // Verify all relays are unique
    let ids: std::collections::HashSet<_> = relays.iter().map(|r| &r.relay.id).collect();
    assert_eq!(ids.len(), 3);

    // Apply circuit obfuscation
    let as_config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let circuit_shield = CircuitShield::new(as_config);
    circuit_shield.initialize().await.unwrap();

    // Register circuits with selected relays
    for (i, selection) in relays.iter().enumerate() {
        circuit_shield.register_circuit(i as u32).await;
    }
}

#[tokio::test]
async fn test_change_tracking_with_relay_operations() {
    // Create change tracker
    let config = ChangeTrackerConfig {
        persist_to_disk: false,
        ..Default::default()
    };
    let tracker = ChangeTracker::with_config(config);

    // Create registry
    let registry = Arc::new(InMemoryRegistry::new());

    // Track relay registration
    let change = SystemChange::new(
        ChangeCategory::Network,
        "Register relay",
        "registry.register(relay)",
        "integration_test",
    );
    let change_id = tracker.record(change).await.unwrap();

    // Register relay
    let relay = RelayInfo::new("192.168.1.1:9001", "test_key", 1_000_000);
    registry.register(relay).await.unwrap();

    // Verify change was tracked
    let tracked_change = tracker.get(change_id).await;
    assert!(tracked_change.is_some());

    // Get all network changes
    let filter = gptl_core::changes::ChangeFilter::new()
        .with_category(ChangeCategory::Network);
    let changes = tracker.get_filtered(&filter).await;
    assert_eq!(changes.len(), 1);
}

#[tokio::test]
async fn test_circuit_failover_with_anti_surveillance() {
    // Setup registry with multiple relays
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..5 {
        let relay = RelayInfo::new(
            format!("10.0.0.{}:9001", i + 1),
            format!("key{}", i),
            10_000_000, // 10 MB/s, well above 1 MB/s minimum
        );
        registry.register(relay).await.unwrap();
    }

    // Create selector
    let selector = Arc::new(RelaySelector::new(registry.clone()));

    // Select initial relay
    let initial_selection = selector.select().await.unwrap();
    let initial_relay_id = initial_selection.relay.id.clone();

    // Report failure
    selector.report_failure(
        &initial_relay_id,
        gptl_core::relay_selector::FailureType::ConnectionFailed
    ).await;

    // Select new relay
    let new_selection = selector.select().await.unwrap();

    // Should get a different relay
    assert_ne!(new_selection.relay.id, initial_relay_id);

    // Apply anti-surveillance to new circuit
    let as_config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let circuit_shield = CircuitShield::new(as_config);
    circuit_shield.initialize().await.unwrap();
    circuit_shield.register_circuit(1).await;
}

#[tokio::test]
async fn test_concurrent_relay_selection() {
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..20 {
        let relay = RelayInfo::new(
            format!("192.168.1.{}:9001", i + 1),
            format!("key{}", i),
            10_000_000, // 10 MB/s, well above 1 MB/s minimum
        );
        registry.register(relay).await.unwrap();
    }

    let selector = Arc::new(RelaySelector::new(registry));

    // Spawn multiple concurrent selection tasks
    let mut handles = vec![];
    for _ in 0..10 {
        let sel = selector.clone();
        let handle = tokio::spawn(async move {
            sel.select().await
        });
        handles.push(handle);
    }

    // Wait for all selections
    let mut selections = vec![];
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        selections.push(result.unwrap());
    }

    assert_eq!(selections.len(), 10);
}

#[tokio::test]
async fn test_anti_surveillance_under_load() {
    let config = Arc::new(RwLock::new(AntiSurveillanceConfig {
        level: SecurityLevel::Maximum,
        ..Default::default()
    }));

    let padding_engine = PaddingEngine::new(config.clone());
    padding_engine.initialize().await.unwrap();

    // Register many circuits
    for i in 0..100 {
        padding_engine.register_circuit(i).await;
    }

    // Process cells for multiple circuits sequentially (avoid Send issues with thread_rng)
    for circuit_id in 0..10 {
        let cells = vec![
            Cell {
                circuit_id,
                stream_id: 1,
                command: CellCommand::Data,
                payload: vec![0u8; 509],
                timestamp: Instant::now(),
            },
        ];
        let result = padding_engine.pad_cells(cells).await;
        assert!(result.is_ok());
    }
}

#[tokio::test]
async fn test_relay_pool_refresh() {
    let registry = Arc::new(InMemoryRegistry::new());

    for i in 0..10 {
        let relay = RelayInfo::new(
            format!("192.168.1.{}:9001", i + 1),
            format!("key{}", i),
            10_000_000, // 10 MB/s, well above 1 MB/s minimum
        );
        registry.register(relay).await.unwrap();
    }

    let selector = Arc::new(RelaySelector::new(registry.clone()));
    let pool = Arc::new(gptl_core::relay_selector::RelayPool::new(selector, 5));

    // Initialize pool
    pool.initialize().await.unwrap();

    // Get relays from pool
    let relay1 = pool.get_relay().await.unwrap();
    let relay2 = pool.get_relay().await.unwrap();

    // Should get valid relays
    assert!(!relay1.relay.id.is_empty());
    assert!(!relay2.relay.id.is_empty());
}

#[tokio::test]
async fn test_security_level_escalation() {
    let mut config = AntiSurveillanceConfig::default();
    config.level = SecurityLevel::Standard;
    let config = Arc::new(RwLock::new(config));

    let padding_engine = PaddingEngine::new(config.clone());
    padding_engine.initialize().await.unwrap();

    let cells = vec![
        Cell {
            circuit_id: 1,
            stream_id: 1,
            command: CellCommand::Data,
            payload: vec![0u8; 509],
            timestamp: Instant::now(),
        },
    ];

    // Process with standard security
    let result1 = padding_engine.pad_cells(cells.clone()).await.unwrap();
    let standard_count = result1.len();

    // Escalate to maximum security
    {
        let mut cfg = config.write().await;
        cfg.level = SecurityLevel::Maximum;
    }

    // Process with maximum security
    let result2 = padding_engine.pad_cells(cells).await.unwrap();
    let maximum_count = result2.len();

    // Maximum security should add more padding
    assert!(maximum_count >= standard_count);
}
