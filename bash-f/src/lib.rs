#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

/// Number of 64-bit words in the state
const STATE_WORDS: usize = 24;

/// Precalculated rotation params
const ROTATION_PARAMS: [(u32, u32, u32, u32); 8] = {
    let mut params = [(0u32, 0u32, 0u32, 0u32); 8];
    let mut m1 = 8u32;
    let mut n1 = 53u32;
    let mut m2 = 14u32;
    let mut n2 = 1u32;

    let mut j = 0;
    while j < 8 {
        params[j] = (m1, n1, m2, n2);
        m1 = (7 * m1) % 64;
        n1 = (7 * n1) % 64;
        m2 = (7 * m2) % 64;
        n2 = (7 * n2) % 64;
        j += 1;
    }
    params
};

/// `bash-s` transformation.
///
/// Implements the S-box transformation defined in Section 6.1 of STB 34.101.77-2020.
/// This is the core non-linear transformation used in the `bash-f` sponge function.
fn bash_s(
    mut w0: u64,
    mut w1: u64,
    mut w2: u64,
    m1: u32,
    n1: u32,
    m2: u32,
    n2: u32,
) -> (u64, u64, u64) {
    // 1. T0 ← RotHi^m1(W0)
    let t0 = w0.rotate_left(m1);

    // 2. W0 ← W0 ⊕ W1 ⊕ W2
    w0 ^= w1 ^ w2;

    // 3. T1 ← W1 ⊕ RotHi^n1(W0)
    let t1 = w1 ^ w0.rotate_left(n1);

    // 4. W1 ← T0 ⊕ T1
    w1 = t0 ^ t1;

    // 5. W2 ← W2 ⊕ RotHi^m2(W2) ⊕ RotHi^n2(T1)
    w2 ^= w2.rotate_left(m2) ^ t1.rotate_left(n2);

    // 6. T0 ← ¬W2
    let t0 = !w2;

    // 7. T1 ← W0 ∨ W2
    let t1 = w0 | w2;

    // 8. T2 ← W0 ∧ W1
    let t2 = w0 & w1;

    // 9. T0 ← T0 ∨ W1
    let t0 = t0 | w1;

    // 10. W1 ← W1 ⊕ T1
    w1 ^= t1;

    // 11. W2 ← W2 ⊕ T2
    w2 ^= t2;

    // 12. W0 ← W0 ⊕ T0
    w0 ^= t0;

    // 13. Return (W0, W1, W2)
    (w0, w1, w2)
}

/// `bash-f` sponge permutation.
///
/// Implements the core sponge function defined in Section 6.2 of STB 34.101.77-2020.
/// This is a cryptographic permutation that operates on 1536-bit states.
///
/// # Parameters
///
/// - `state`: Mutable reference to 24 × 64-bit words (1536 bits total) in little-endian internal representation
pub fn bash_f(state: &mut [u64; STATE_WORDS]) {
    // 1. Split S into words (S0, S1, ..., S23)

    // 2. C ← B194BAC80A08F53B (initialize round constant, swapped to little-endian)
    let mut c: u64 = 0x3BF5080AC8BA94B1;

    // 3. For i = 1, 2, ..., 24 perform 24 rounds
    for _ in 0..STATE_WORDS {
        // 3.1. Apply S-box layer with varying rotation parameters
        // (m1, n1, m2, n2) ← (8, 53, 14, 1)

        // 3.2. For j = 0, 1, ..., 7 apply bash-s to each of 8 columns
        // 3.2.a. (Sj, S8+j, S16+j) ← bash-s(Sj, S8+j, S16+j, m1, n1, m2, n2)
        // 3.2.b. (m1, n1, m2, n2) ← (7·m1 mod 64, 7·n1 mod 64, 7·m2 mod 64, 7·n2 mod 64)
        macro_rules! apply_s_box {
            ($j:expr) => {{
                let (m1, n1, m2, n2) = ROTATION_PARAMS[$j];
                let (s0, s1, s2) = bash_s(state[$j], state[8 + $j], state[16 + $j], m1, n1, m2, n2);
                state[$j] = s0;
                state[8 + $j] = s1;
                state[16 + $j] = s2;
            }};
        }

        #[cfg(feature = "no_unroll")]
        for j in 0..8 {
            apply_s_box!(j);
        }

        #[cfg(not(feature = "no_unroll"))]
        {
            apply_s_box!(0);
            apply_s_box!(1);
            apply_s_box!(2);
            apply_s_box!(3);
            apply_s_box!(4);
            apply_s_box!(5);
            apply_s_box!(6);
            apply_s_box!(7);
        }

        // 3.3. Apply word permutation
        // S ← S15 ‖ S10 ‖ S9 ‖ S12 ‖ S11 ‖ S14 ‖ S13 ‖ S8 ‖
        //     S17 ‖ S16 ‖ S19 ‖ S18 ‖ S21 ‖ S20 ‖ S23 ‖ S22 ‖
        //     S6 ‖ S3 ‖ S0 ‖ S5 ‖ S2 ‖ S7 ‖ S4 ‖ S1
        const INDEXES: [usize; STATE_WORDS] = [
            15, 10, 9, 12, 11, 14, 13, 8, 17, 16, 19, 18, 21, 20, 23, 22, 6, 3, 0, 5, 2, 7, 4, 1,
        ];
        *state = INDEXES.map(|i| state[i]);

        // 3.4. S23 ← S23 ⊕ C (add round constant)
        state[23] ^= c;

        // 3.5. Update LFSR (Galois configuration)
        // if ⌊C⌉ is even, then C ← ShLo(C)
        // else C ← ShLo(C) ⊕ AED8E07F99E12BDC
        if c & 1 == 0 {
            c >>= 1;
        } else {
            c = (c >> 1) ^ 0xDC2BE1997FE0D8AE;
        }
    }

    // 4. Return S - state is modified in place
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from Table A.1 of STB 34.101.77-2020.
    #[test]
    fn test_bash_s_table_a1() {
        // Constants in the spec are given using LE order
        // For example, in spec when they write B194BAC80A08F53B, they do not mean 0xB194BAC80A08F53B, but 0x3BF5080AC8BA94B1.
        // https://github.com/RustCrypto/sponges/pull/92#issuecomment-3433315011
        let w0 = 0xB194BAC80A08F53Bu64.swap_bytes();
        let w1 = 0xE12BDC1AE28257ECu64.swap_bytes();
        let w2 = 0xE9DEE72C8F0C0FA6u64.swap_bytes();

        let (w0_out, w1_out, w2_out) = bash_s(w0, w1, w2, 8, 53, 14, 1);

        assert_eq!(w0_out, 0x479E76129979DC5Fu64.swap_bytes());
        assert_eq!(w1_out, 0x0F2B2C93ED128EDDu64.swap_bytes());
        assert_eq!(w2_out, 0x41009B1B112DFEF3u64.swap_bytes());
    }
}
