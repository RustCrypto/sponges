#![feature(test)]
extern crate keccak;
extern crate test;

use keccak::{f1600, f200, f400, f800};

macro_rules! impl_bench {
    ($name:ident, $fn:ident, $type:expr) => {
        #[bench]
        fn $name(b: &mut test::Bencher) {
            let mut data = [$type; 25];
            b.iter(|| $fn(&mut data));
        }
    };
}

impl_bench!(b_f200, f200, 0u8);
impl_bench!(b_f400, f400, 0u16);
impl_bench!(b_f800, f800, 0u32);
impl_bench!(b_f1600, f1600, 0u64);
