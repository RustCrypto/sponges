use criterion::{criterion_group, criterion_main, Criterion};

fn criterion_bench_permutation(c: &mut Criterion) {
    let mut state = core::hint::black_box([
        0xd0764d4f4476689f,
        0x519e4174576f3791,
        0xfbe07cfb0c24ed8c,
        0xb37d9f600cd835b8,
        0xcb231c3874846a73,
    ]);

    let mut c = c.benchmark_group("Permutation");

    c.bench_function("1 round", |b| b.iter(|| ascon::permute1(&mut state)));
    c.bench_function("6 rounds", |b| b.iter(|| ascon::permute6(&mut state)));
    c.bench_function("8 rounds", |b| b.iter(|| ascon::permute8(&mut state)));
    c.bench_function("12 rounds", |b| b.iter(|| ascon::permute12(&mut state)));

    core::hint::black_box(state);

    c.finish();
}

criterion_group!(bench_permutation, criterion_bench_permutation);
criterion_main!(bench_permutation);
