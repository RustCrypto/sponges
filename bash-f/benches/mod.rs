#![feature(test)]
extern crate test;

use bash_f::bash_f;
use test::Bencher;

const STATE_WORDS: usize = 24;

#[bench]
fn bench_bash_f(b: &mut Bencher) {
    let mut state = [0u64; STATE_WORDS];
    b.iter(|| {
        bash_f(test::black_box(&mut state));
        test::black_box(&state);
    });
}

#[bench]
fn bench_bash_f_10_rounds(b: &mut Bencher) {
    let mut state = [0u64; STATE_WORDS];
    b.iter(|| {
        for _ in 0..10 {
            bash_f(test::black_box(&mut state));
        }
        test::black_box(&state);
    });
}

#[bench]
fn bench_bash_f_100_rounds(b: &mut Bencher) {
    let mut state = [0u64; STATE_WORDS];
    b.iter(|| {
        for _ in 0..100 {
            bash_f(test::black_box(&mut state));
        }
        test::black_box(&state);
    });
}
