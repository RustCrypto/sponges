use super::{PI, PLEN, RC, RHO};

extern crate packed_simd;
use self::packed_simd::{u64x2,u64x4,u64x8};

macro_rules! create_function {
    ($func_name:ident, $type:ty) => (
        #[allow(unused_assignments)]
        /// Keccak-f[1600] sponge function
        pub fn $func_name(a: &mut [$type; PLEN]) {
            // not unrolling this loop results in a much smaller function, plus
            // it positively influences performance due to the smaller load on I-cache
            for i in 0..24 {
                let mut array: [$type; 5] = Default::default();

                // Theta
                unroll5!(x, {
                    unroll5!(y, {
                        array[x] ^= a[5 * y + x];
                    });
                });

                unroll5!(x, {
                    unroll5!(y, {
                        let t1 = array[(x + 4) % 5];
                        let t2 = array[(x + 1) % 5].rotate_left(<$type>::splat(1));
                        a[5 * y + x] ^= t1 ^ t2;
                    });
                });

                // Rho and pi
                let mut last = a[1];
                unroll24!(x, {
                    array[0] = a[PI[x]];
                    a[PI[x]] = last.rotate_left(<$type>::splat(RHO[x] as u64));
                    last = array[0];
                });

                // Chi
                unroll5!(y_step, {
                    let y = 5 * y_step;

                    unroll5!(x, {
                        array[x] = a[y + x];
                    });

                    unroll5!(x, {
                        let t1 = !array[(x + 1) % 5];
                        let t2 = array[(x + 2) % 5];
                        a[y + x] = array[x] ^ (t1 & t2);
                    });
                });

                // Iota
                a[0] ^= RC[i];
            }
        }
    );
}

create_function!(f1600x2, u64x2);
create_function!(f1600x4, u64x4);
create_function!(f1600x8, u64x8);

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::f1600;

    extern crate rand_core;
    extern crate rand_os;

    use self::rand_core::RngCore;
    use self::rand_os::OsRng;

    macro_rules! create_test {
        ($test_name:ident, $func_name:ident, $type:ty) => (
            #[test]
            fn $test_name() {
                let mut rng = OsRng::new().unwrap();
                for _ in 0..100 {
                    // Create random vector
                    let mut buf : [$type;25] = Default::default();
                    let mut buf2 = [0u64;25];
                    for j in 0..25 {
                        buf2[j] = rng.next_u64();
                        buf[j] = <$type>::splat(buf2[j]);
                    }

                    // Apply reference f1600 and f1600xn
                    f1600(&mut buf2);
                    $func_name(&mut buf);

                    // Test
                    for j in 0..25 {
                        for l in 0..<$type>::lanes() {
                            assert_eq!(buf2[j], buf[j].extract(l));
                        }
                    }
                }
            }
        );
    }

    create_test!(test_f1600x2, f1600x2, u64x2);
    create_test!(test_f1600x4, f1600x4, u64x4);
    create_test!(test_f1600x8, f1600x8, u64x8);
}

