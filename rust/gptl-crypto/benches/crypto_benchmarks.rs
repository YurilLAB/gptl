use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gptl_crypto::{
    aead::{AeadCipher, CipherSuite},
    kex::{KeyExchange, KexAlgorithm},
    ratchet::DoubleRatchet,
};

fn bench_aead_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_encryption");

    let cipher = AeadCipher::new(CipherSuite::ChaCha20Poly1305).unwrap();
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];

    for size in [64, 512, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::new("ChaCha20Poly1305", size), size, |b, _| {
            b.iter(|| {
                cipher.encrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&plaintext),
                    black_box(&[])
                ).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_aead_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_decryption");

    let cipher = AeadCipher::new(CipherSuite::ChaCha20Poly1305).unwrap();
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];

    for size in [64, 512, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        let ciphertext = cipher.encrypt(&key, &nonce, &plaintext, &[]).unwrap();

        group.bench_with_input(BenchmarkId::new("ChaCha20Poly1305", size), size, |b, _| {
            b.iter(|| {
                cipher.decrypt(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(&ciphertext),
                    black_box(&[])
                ).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_key_exchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");

    // X25519 benchmark
    let kex_x25519 = KeyExchange::new(KexAlgorithm::X25519).unwrap();
    group.bench_function("X25519_keygen", |b| {
        b.iter(|| {
            black_box(kex_x25519.generate_keypair().unwrap())
        });
    });

    let (alice_pub, alice_priv) = kex_x25519.generate_keypair().unwrap();
    let (bob_pub, _bob_priv) = kex_x25519.generate_keypair().unwrap();

    group.bench_function("X25519_derive", |b| {
        b.iter(|| {
            black_box(kex_x25519.derive_shared_secret(
                &alice_priv,
                &bob_pub
            ).unwrap())
        });
    });

    // Hybrid PQ benchmark
    let kex_hybrid = KeyExchange::new(KexAlgorithm::HybridPQ).unwrap();
    group.bench_function("HybridPQ_keygen", |b| {
        b.iter(|| {
            black_box(kex_hybrid.generate_keypair().unwrap())
        });
    });

    let (alice_pub_pq, alice_priv_pq) = kex_hybrid.generate_keypair().unwrap();
    let (bob_pub_pq, _bob_priv_pq) = kex_hybrid.generate_keypair().unwrap();

    group.bench_function("HybridPQ_derive", |b| {
        b.iter(|| {
            black_box(kex_hybrid.derive_shared_secret(
                &alice_priv_pq,
                &bob_pub_pq
            ).unwrap())
        });
    });

    group.finish();
}

fn bench_double_ratchet(c: &mut Criterion) {
    let mut group = c.benchmark_group("double_ratchet");

    let shared_secret = vec![0u8; 32];
    let mut alice = DoubleRatchet::new_alice(shared_secret.clone()).unwrap();
    let mut bob = DoubleRatchet::new_bob(shared_secret).unwrap();

    // Initialize ratchet
    let (alice_pub, _) = KeyExchange::new(KexAlgorithm::X25519)
        .unwrap()
        .generate_keypair()
        .unwrap();
    bob.ratchet_encrypt(&alice_pub, b"init").unwrap();

    let plaintext = b"Hello, World!";

    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let (bob_pub, _) = KeyExchange::new(KexAlgorithm::X25519)
                .unwrap()
                .generate_keypair()
                .unwrap();
            black_box(alice.ratchet_encrypt(&bob_pub, black_box(plaintext)).unwrap())
        });
    });

    group.finish();
}

fn bench_cell_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("cell_encryption");

    let cipher = AeadCipher::new(CipherSuite::ChaCha20Poly1305).unwrap();
    let key = vec![0u8; 32];

    // Tor cell size is 514 bytes (509 payload + 5 header)
    let cell_payload = vec![0u8; 509];

    group.bench_function("encrypt_cell", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            let nonce = counter.to_le_bytes().to_vec();
            counter += 1;
            black_box(cipher.encrypt(
                &key,
                &nonce,
                black_box(&cell_payload),
                &[]
            ).unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_aead_encryption,
    bench_aead_decryption,
    bench_key_exchange,
    bench_double_ratchet,
    bench_cell_encryption
);
criterion_main!(benches);
