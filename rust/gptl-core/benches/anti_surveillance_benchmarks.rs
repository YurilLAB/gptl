use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gptl_core::{
    anti_surveillance::{
        AntiSurveillanceConfig, SecurityLevel, Cell, CellCommand,
        padding::PaddingEngine,
        timing_protection::TimingDefense,
        traffic_shaping::TrafficShaper,
        circuit_obfuscation::CircuitShield,
    },
};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Instant;

fn create_test_cells(count: usize, circuit_id: u32) -> Vec<Cell> {
    (0..count)
        .map(|i| Cell {
            circuit_id,
            stream_id: (i % 256) as u16,
            command: CellCommand::Data,
            payload: vec![0u8; 509],
            timestamp: Instant::now(),
        })
        .collect()
}

fn bench_padding_standard(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("padding_standard");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig {
        level: SecurityLevel::Standard,
        ..Default::default()
    }));

    let engine = PaddingEngine::new(config);
    rt.block_on(engine.initialize()).unwrap();

    for size in [1, 10, 50, 100].iter() {
        let cells = create_test_cells(*size, 1);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                black_box(engine.pad_cells(cells).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_padding_enhanced(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("padding_enhanced");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig {
        level: SecurityLevel::Enhanced,
        ..Default::default()
    }));

    let engine = PaddingEngine::new(config);
    rt.block_on(engine.initialize()).unwrap();

    for size in [1, 10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                black_box(engine.pad_cells(cells).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_padding_maximum(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("padding_maximum");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig {
        level: SecurityLevel::Maximum,
        ..Default::default()
    }));

    let engine = PaddingEngine::new(config);
    rt.block_on(engine.initialize()).unwrap();

    for size in [1, 10, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                black_box(engine.pad_cells(cells).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_timing_defense(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("timing_defense");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let defense = TimingDefense::new(config);
    rt.block_on(defense.initialize()).unwrap();

    for size in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                black_box(defense.apply_timing_defense(cells).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_traffic_shaping(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("traffic_shaping");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let shaper = TrafficShaper::new(config);
    rt.block_on(shaper.initialize()).unwrap();

    for size in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                black_box(shaper.shape_traffic(cells).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_circuit_obfuscation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("circuit_obfuscation");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let shield = CircuitShield::new(config);
    rt.block_on(shield.initialize()).unwrap();

    group.bench_function("register_circuit", |b| {
        b.to_async(&rt).iter(|| async {
            let circuit_id = rand::random::<u32>();
            black_box(shield.register_circuit(circuit_id).await)
        });
    });

    group.bench_function("obfuscate_cells", |b| {
        b.to_async(&rt).iter(|| async {
            let cells = create_test_cells(10, 1);
            black_box(shield.obfuscate_cells(cells).await.unwrap())
        });
    });

    group.finish();
}

fn bench_full_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("full_pipeline");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig {
        level: SecurityLevel::Enhanced,
        ..Default::default()
    }));

    let padding = PaddingEngine::new(config.clone());
    let timing = TimingDefense::new(config.clone());
    let shaping = TrafficShaper::new(config.clone());

    rt.block_on(async {
        padding.initialize().await.unwrap();
        timing.initialize().await.unwrap();
        shaping.initialize().await.unwrap();
    });

    for size in [10, 50].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.to_async(&rt).iter(|| async {
                let cells = create_test_cells(*size, 1);
                let padded = padding.pad_cells(cells).await.unwrap();
                let timed = timing.apply_timing_defense(padded).await.unwrap();
                black_box(shaping.shape_traffic(timed).await.unwrap())
            });
        });
    }

    group.finish();
}

fn bench_concurrent_circuits(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_circuits");

    let config = Arc::new(RwLock::new(AntiSurveillanceConfig::default()));
    let padding = Arc::new(PaddingEngine::new(config));
    rt.block_on(padding.initialize()).unwrap();

    for num_circuits in [5, 10, 20].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(num_circuits), num_circuits, |b, &n| {
            b.to_async(&rt).iter(|| async {
                let mut handles = vec![];
                for i in 0..n {
                    let p = padding.clone();
                    let handle = tokio::spawn(async move {
                        let cells = create_test_cells(10, i as u32);
                        p.pad_cells(cells).await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    black_box(handle.await.unwrap().unwrap());
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_padding_standard,
    bench_padding_enhanced,
    bench_padding_maximum,
    bench_timing_defense,
    bench_traffic_shaping,
    bench_circuit_obfuscation,
    bench_full_pipeline,
    bench_concurrent_circuits
);
criterion_main!(benches);
