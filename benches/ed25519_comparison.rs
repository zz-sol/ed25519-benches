use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::{traits::MultiscalarMul, EdwardsPoint, Scalar};
use ed25519_benches::firedancer_ffi;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use ed25519_zebra::{SigningKey as ZebraSigningKey, VerificationKey as ZebraVerificationKey};
use rand::rngs::OsRng;
use rand::RngCore;

// Helper function to generate test data
fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

fn random_scalar() -> Scalar {
    let mut csprng = OsRng;
    let mut bytes = [0u8; 64];
    csprng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

// Benchmark: Key Generation
fn bench_keygen(c: &mut Criterion) {
    c.bench_function("dalek_keygen", |b| {
        b.iter(|| {
            let mut csprng = OsRng;
            let mut secret_bytes = [0u8; 32];
            csprng.fill_bytes(&mut secret_bytes);
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            black_box(signing_key)
        })
    });

    c.bench_function("firedancer_keygen", |b| {
        b.iter(|| {
            let mut csprng = OsRng;
            let mut secret_bytes = [0u8; 32];
            csprng.fill_bytes(&mut secret_bytes);
            let public_key = firedancer_ffi::public_from_private(&secret_bytes).unwrap();
            black_box(public_key)
        })
    });

    c.bench_function("zebra_keygen", |b| {
        b.iter(|| {
            let mut csprng = OsRng;
            let mut secret_bytes = [0u8; 32];
            csprng.fill_bytes(&mut secret_bytes);
            let signing_key = ZebraSigningKey::from(secret_bytes);
            let verification_key = ZebraVerificationKey::from(&signing_key);
            black_box(verification_key)
        })
    });
}

// Benchmark: Signing
fn bench_sign(c: &mut Criterion) {
    let (signing_key, _) = generate_keypair();
    let message = b"This is a test message for benchmarking Ed25519 signing";

    c.bench_function("dalek_sign", |b| {
        b.iter(|| {
            let signature = signing_key.sign(black_box(message));
            black_box(signature)
        })
    });

    let mut csprng = OsRng;
    let mut private_key = [0u8; 32];
    csprng.fill_bytes(&mut private_key);
    let public_key = firedancer_ffi::public_from_private(&private_key).unwrap();

    c.bench_function("firedancer_sign", |b| {
        b.iter(|| {
            let signature =
                firedancer_ffi::sign(black_box(message), &public_key, &private_key).unwrap();
            black_box(signature)
        })
    });

    let mut csprng = OsRng;
    let mut zebra_secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut zebra_secret_bytes);
    let zebra_signing_key = ZebraSigningKey::from(zebra_secret_bytes);

    c.bench_function("zebra_sign", |b| {
        b.iter(|| {
            let signature = zebra_signing_key.sign(black_box(message));
            black_box(signature)
        })
    });
}

// Benchmark: Verification
fn bench_verify(c: &mut Criterion) {
    let (signing_key, verifying_key) = generate_keypair();
    let message = b"This is a test message for benchmarking Ed25519 verification";
    let signature = signing_key.sign(message);

    c.bench_function("dalek_verify", |b| {
        b.iter(|| {
            let result = verifying_key.verify(black_box(message), black_box(&signature));
            black_box(result)
        })
    });

    let mut csprng = OsRng;
    let mut private_key = [0u8; 32];
    csprng.fill_bytes(&mut private_key);
    let public_key = firedancer_ffi::public_from_private(&private_key).unwrap();
    let fd_signature = firedancer_ffi::sign(message, &public_key, &private_key).unwrap();

    c.bench_function("firedancer_verify", |b| {
        b.iter(|| {
            let result =
                firedancer_ffi::verify(black_box(message), black_box(&fd_signature), &public_key);
            black_box(result)
        })
    });

    let mut csprng = OsRng;
    let mut zebra_secret_bytes = [0u8; 32];
    csprng.fill_bytes(&mut zebra_secret_bytes);
    let zebra_signing_key = ZebraSigningKey::from(zebra_secret_bytes);
    let zebra_verification_key = ZebraVerificationKey::from(&zebra_signing_key);
    let zebra_signature = zebra_signing_key.sign(message);

    c.bench_function("zebra_verify", |b| {
        b.iter(|| {
            let result = zebra_verification_key.verify(black_box(&zebra_signature), black_box(message));
            black_box(result)
        })
    });
}

// Benchmark: Batch Verification (2^2 to 2^12)
fn bench_batch_verify(c: &mut Criterion) {
    // Benchmark both implementations side-by-side for each size
    for i in 2..=12 {
        // Firedancer batch verify is limited to 255 signatures (2^8)
        let size = 1 << i;

        // Dalek: Individual verification of multiple signatures (different messages)
        {
            let mut group = c.benchmark_group("batch_verify");

            // Generate test data for Dalek
            let mut messages = Vec::new();
            let mut signatures = Vec::new();
            let mut public_keys = Vec::new();

            for _ in 0..size {
                let (signing_key, verifying_key) = generate_keypair();
                let message = format!("Message {}", rand::random::<u64>());
                let signature = signing_key.sign(message.as_bytes());

                messages.push(message.into_bytes());
                signatures.push(signature);
                public_keys.push(verifying_key);
            }

            group.bench_with_input(BenchmarkId::new("dalek", size), &size, |b, _| {
                b.iter(|| {
                    // Note: ed25519-dalek v2 doesn't have built-in batch verification
                    // We'll verify each signature individually
                    for i in 0..size {
                        let _ = public_keys[i]
                            .verify(black_box(&messages[i]), black_box(&signatures[i]));
                    }
                })
            });

            // Firedancer: Batch verification over the same message
            let message = b"Batch verification test message";
            let mut fd_signatures = Vec::new();
            let mut fd_public_keys = Vec::new();

            for _ in 0..size {
                let mut csprng = OsRng;
                let mut private_key = [0u8; 32];
                csprng.fill_bytes(&mut private_key);
                let public_key = firedancer_ffi::public_from_private(&private_key).unwrap();
                let signature = firedancer_ffi::sign(message, &public_key, &private_key).unwrap();

                fd_signatures.push(signature);
                fd_public_keys.push(public_key);
            }

            group.bench_with_input(BenchmarkId::new("firedancer", size), &size, |b, _| {
                b.iter(|| {
                    let result = firedancer_ffi::verify_batch_single_msg(
                        black_box(message),
                        black_box(&fd_signatures),
                        black_box(&fd_public_keys),
                    );
                    black_box(result)
                })
            });

            // Zebra: Batch verification
            let mut zebra_items = Vec::new();
            for _ in 0..size {
                let mut csprng = OsRng;
                let mut secret_bytes = [0u8; 32];
                csprng.fill_bytes(&mut secret_bytes);
                let signing_key = ZebraSigningKey::from(secret_bytes);
                let vk_bytes = ed25519_zebra::VerificationKeyBytes::from(&signing_key);
                let signature = signing_key.sign(message);

                zebra_items.push((vk_bytes, signature, message));
            }

            group.bench_with_input(BenchmarkId::new("zebra", size), &size, |b, _| {
                b.iter(|| {
                    let mut batch = ed25519_zebra::batch::Verifier::new();
                    for (vk, sig, msg) in &zebra_items {
                        batch.queue((black_box(*vk), black_box(*sig), black_box(msg)));
                    }
                    let result = batch.verify(OsRng);
                    black_box(result)
                })
            });

            group.finish();
        }
    }
}

// Benchmark: Single Group Multiplication
fn bench_single_scalar_mul(c: &mut Criterion) {
    let scalar = random_scalar();
    let point = EdwardsPoint::default();

    c.bench_function("dalek_scalar_mul", |b| {
        b.iter(|| {
            let result = black_box(&point) * black_box(&scalar);
            black_box(result)
        })
    });
}

// Benchmark: Multi-Scalar Multiplication (MSM) for 2^2 to 2^12
fn bench_msm(c: &mut Criterion) {
    let mut group = c.benchmark_group("dalek_msm");

    for i in 2..=12 {
        let size = 1 << i;

        // Generate random scalars and points
        let scalars: Vec<Scalar> = (0..size).map(|_| random_scalar()).collect();

        let points: Vec<EdwardsPoint> = (0..size)
            .map(|_| EdwardsPoint::default() * random_scalar())
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                let result = EdwardsPoint::multiscalar_mul(black_box(&scalars), black_box(&points));
                black_box(result)
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_batch_verify,
    bench_single_scalar_mul,
    bench_msm
);
criterion_main!(benches);
