#![feature(test)]
extern crate keccak;
extern crate test;

#[bench]
fn f1600(b: &mut test::Bencher) {
    let mut data = [0u64; 25];
    b.iter(|| keccak::f1600(&mut data));
}

#[cfg(feature = "simd")]
mod simd {
    extern crate packed_simd;
    use self::packed_simd::{u64x2,u64x4,u64x8};

    #[bench]
    fn f1600x2(b: &mut test::Bencher) {
        let mut data: [u64x2; 25] = Default::default();
        b.iter(|| keccak::f1600x2(&mut data));
    }

    #[bench]
    fn f1600x4(b: &mut test::Bencher) {
        let mut data: [u64x4; 25] = Default::default();
        b.iter(|| keccak::f1600x4(&mut data));
    }

    #[bench]
    fn f1600x8(b: &mut test::Bencher) {
        let mut data: [u64x8; 25] = Default::default();
        b.iter(|| keccak::f1600x8(&mut data));
    }
}
