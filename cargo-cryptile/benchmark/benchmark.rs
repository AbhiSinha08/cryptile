use criterion::{criterion_group, criterion_main, Criterion};
use cargo_cryptile::benches::*;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample-size-example");
    group.sample_size(50);
    group.bench_function("encrypt file serially", |b| b.iter(|| bench_serially_encrypt("test.txt")));
    group.bench_function("encrypt file parallelly", |b| b.iter(|| bench_parallelly_encrypt("test.txt")));
    group.bench_function("decrypt file serially", |b| b.iter(|| bench_serially_decrypt("test.txt")));
    group.bench_function("decrypt file parallelly", |b| b.iter(|| bench_parallelly_decrypt("test.txt")));
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);