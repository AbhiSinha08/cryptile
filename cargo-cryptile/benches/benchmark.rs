use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cargo_cryptile;

fn criterion_benchmark(c: &mut Criterion) {
    // c.bench_function("encrypt file", |b| b.iter(|| encrypt_file()));
    // c.bench_function("decrypt file", |b| b.iter(|| decrypt_file()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);