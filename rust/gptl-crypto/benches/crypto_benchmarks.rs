//! Microbenchmarks for the actual gptl-crypto public API.
//!
//! The previous version of this file imported a fictitious API
//! (`AeadCipher`, `KeyExchange`, `DoubleRatchet`) and failed to compile.
//! These benches target the real types: `AesGcmCipher`, `ChaCha20Cipher`,
//! `X25519KeyExchange`, `HybridKeyExchange`, and `KeyRatchet`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use gptl_crypto::aead::{AesGcmCipher, CellCipher, ChaCha20Cipher};
use gptl_crypto::kex::{HybridKeyExchange, KeyExchange, X25519KeyExchange};
use gptl_crypto::ratchet::KeyRatchet;
use gptl_crypto::SharedSecret;
use zeroize::Zeroizing;

fn bench_aead_encryption(c: &mut Criterion) {
    let key = [0u8; 32];
    let aes = AesGcmCipher::new(&key, [1, 2, 3, 4]).unwrap();
    let cha = ChaCha20Cipher::new(&key, [1, 2, 3, 4]).unwrap();

    let mut group = c.benchmark_group("aead_encryption");
    for size in [64usize, 512, 1024, 4096].iter() {
        let plaintext = vec![0xAAu8; *size];
        group.bench_with_input(BenchmarkId::new("AES-256-GCM", size), size, |b, _| {
            b.iter(|| aes.encrypt(black_box(&plaintext)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("ChaCha20-Poly1305", size), size, |b, _| {
            b.iter(|| cha.encrypt(black_box(&plaintext)).unwrap());
        });
    }
    group.finish();
}

fn bench_x25519_kex(c: &mut Criterion) {
    let kex = X25519KeyExchange::new();
    c.bench_function("x25519_keypair_then_derive", |b| {
        b.iter(|| {
            let (apk, ask) = kex.generate_keypair().unwrap();
            let (bpk, bsk) = kex.generate_keypair().unwrap();
            let _a = kex.compute_shared(&ask, &bpk).unwrap();
            let _b = kex.compute_shared(&bsk, &apk).unwrap();
        });
    });
}

fn bench_hybrid_kex(c: &mut Criterion) {
    let hybrid = HybridKeyExchange::new();
    let x = X25519KeyExchange::new();
    c.bench_function("hybrid_x25519_mlkem768_encap_decap", |b| {
        b.iter(|| {
            let (pk, sk) = x.generate_keypair().unwrap();
            let encap = hybrid.encapsulate(&pk).unwrap();
            let _ = hybrid.decapsulate(&sk, &encap.ciphertext).unwrap();
        });
    });
}

fn bench_ratchet_next_send(c: &mut Criterion) {
    let secret = SharedSecret(Zeroizing::new(vec![0x42u8; 32]));
    let mut ratchet = KeyRatchet::new(&secret).unwrap();
    c.bench_function("ratchet_next_send_key", |b| {
        b.iter(|| black_box(ratchet.next_send_key().unwrap()));
    });
}

criterion_group!(
    benches,
    bench_aead_encryption,
    bench_x25519_kex,
    bench_hybrid_kex,
    bench_ratchet_next_send,
);
criterion_main!(benches);
