//! bash-f benchmarks

#![feature(test)]
extern crate test;

use bash_f::{STATE_WORDS, bash_f};
use test::Bencher;

#[bench]
fn bench_bash_f(b: &mut Bencher) {
    let state = &mut [0u64; STATE_WORDS];
    b.iter(|| bash_f(test::black_box(state)));
}
