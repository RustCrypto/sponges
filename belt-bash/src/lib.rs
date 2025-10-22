//! # BelHash - STB 34.101.77-2020 Sponge-Based Cryptographic Algorithms
//!
//! This module implements the cryptographic algorithms defined in the Belarusian
//! state standard STB 34.101.77-2020 "Sponge-based cryptographic algorithms".
//!
//! ## Overview
//!
//! The standard defines a family of cryptographic algorithms built on a sponge
//! construction with the `bash-f` sponge function at its core. The sponge function
//! operates on 1536-bit (192-byte) states.
//!
//! ## Components
//!
//! ### Core Primitives
//!
//! - **bash-s**: S-box transformation operating on three 64-bit words
//! - **bash-f**: Sponge permutation function (24 rounds)
//!
//! ### High-Level Algorithms
//!
//! - Hash functions (128-256 bit security levels)
//! - Authenticated encryption
//! - AEAD (Authenticated Encryption with Associated Data)
//!
//! ## Security Levels
//!
//! The standard supports three security levels:
//! - ℓ = 128 bits
//! - ℓ = 192 bits
//! - ℓ = 256 bits
//!
//! ## References
//!
//! - STB 34.101.77-2020 specification
//! - [Official standard](http://apmi.bsu.by/assets/files/std/bash-spec324.pdf)
//!
//! ## Note on Byte Order
//!
//! The specification uses big-endian representation for test vectors, while
//! internal computation uses little-endian.
//! The public API handles byte swapping automatically.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_upper_case_globals)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

/// Number of 64-bit words in the state
const STATE_WORDS: usize = 24;

/// Internal bash-s transformation.
///
/// Implements the S-box transformation defined in Section 6.1 of STB 34.101.77-2020.
/// This is the core non-linear transformation used in the bash-f sponge function.
fn bash_s_internal(
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

/// bash-s transformation with standard-compliant byte order.
///
/// This is the public interface to the bash-s algorithm as defined in
/// Section 6.1 of STB 34.101.77-2020. It handles conversion between
/// the standard's big-endian representation and the internal little-endian
/// computation.
/// ```rust
/// use bash::bash_s;
/// let w0 = 0xB194BAC80A08F53B;
/// let w1 = 0xE12BDC1AE28257EC;
/// let w2 = 0xE9DEE72C8F0C0FA6;
/// let (r0, r1, r2) = bash_s(w0, w1, w2, 8, 53, 14, 1);
/// assert_eq!(r0, 0x479E76129979DC5F);
/// assert_eq!(r1, 0x0F2B2C93ED128EDD);
/// assert_eq!(r2, 0x41009B1B112DFEF3);
/// ```
pub fn bash_s(w0: u64, w1: u64, w2: u64, m1: u32, n1: u32, m2: u32, n2: u32) -> (u64, u64, u64) {
    // Convert from big-endian (standard) to little-endian (internal)
    let (w0_out, w1_out, w2_out) = bash_s_internal(
        w0.swap_bytes(),
        w1.swap_bytes(),
        w2.swap_bytes(),
        m1,
        n1,
        m2,
        n2,
    );

    // Convert back to big-endian for output
    (
        w0_out.swap_bytes(),
        w1_out.swap_bytes(),
        w2_out.swap_bytes(),
    )
}

/// Internal bash-f sponge permutation.
///
/// Implements the core sponge function defined in Section 6.2 of STB 34.101.77-2020.
/// This is a cryptographic permutation that operates on 1536-bit states.
///
/// # Parameters
///
/// - `state`: Mutable reference to 24 × 64-bit words (1536 bits total) in little-endian internal representation
fn bash_f_internal(state: &mut [u64; STATE_WORDS]) {
    // 1. Split S into words (S0, S1, ..., S23)

    // 2. C ← B194BAC80A08F53B (initialize round constant, swapped to little-endian)
    let mut c: u64 = 0xB194BAC80A08F53Bu64.swap_bytes();

    // 3. For i = 1, 2, ..., 24 perform 24 rounds
    for _ in 0..STATE_WORDS {
        // 3.1. Apply S-box layer with varying rotation parameters
        // (m1, n1, m2, n2) ← (8, 53, 14, 1)
        let mut m1 = 8u32;
        let mut n1 = 53u32;
        let mut m2 = 14u32;
        let mut n2 = 1u32;

        // 3.2. For j = 0, 1, ..., 7 apply bash-s to each of 8 columns
        for j in 0..8 {
            // 3.2.a. (Sj, S8+j, S16+j) ← bash-s(Sj, S8+j, S16+j, m1, n1, m2, n2)
            let (s0, s1, s2) =
                bash_s_internal(state[j], state[8 + j], state[16 + j], m1, n1, m2, n2);
            state[j] = s0;
            state[8 + j] = s1;
            state[16 + j] = s2;

            // 3.2.b. (m1, n1, m2, n2) ← (7·m1 mod 64, 7·n1 mod 64, 7·m2 mod 64, 7·n2 mod 64)
            m1 = (7 * m1) % 64;
            n1 = (7 * n1) % 64;
            m2 = (7 * m2) % 64;
            n2 = (7 * n2) % 64;
        }

        // 3.3. Apply word permutation π
        // S ← S15 ‖ S10 ‖ S9 ‖ S12 ‖ S11 ‖ S14 ‖ S13 ‖ S8 ‖
        //     S17 ‖ S16 ‖ S19 ‖ S18 ‖ S21 ‖ S20 ‖ S23 ‖ S22 ‖
        //     S6 ‖ S3 ‖ S0 ‖ S5 ‖ S2 ‖ S7 ‖ S4 ‖ S1
        let temp = [
            state[15], state[10], state[9], state[12], state[11], state[14], state[13], state[8],
            state[17], state[16], state[19], state[18], state[21], state[20], state[23], state[22],
            state[6], state[3], state[0], state[5], state[2], state[7], state[4], state[1],
        ];
        state.copy_from_slice(&temp);

        // 3.4. S23 ← S23 ⊕ C (add round constant)
        state[23] ^= c;

        // 3.5. Update LFSR (Galois configuration)
        // if ⌊C⌉ is even, then C ← ShLo(C)
        // else C ← ShLo(C) ⊕ AED8E07F99E12BDC
        if c & 1 == 0 {
            c >>= 1;
        } else {
            c = (c >> 1) ^ 0xAED8E07F99E12BDCu64.swap_bytes();
        }
    }

    // 4. Return S - state is modified in place
}

/// bash-f sponge function with standard-compliant interface.
///
/// This is the public interface as specified in Section 6.2 of STB 34.101.77-2020.
/// It accepts and returns states in big-endian byte order as per the standard.
///
/// # Parameters
///
/// - `state`: Mutable array of 24 × 64-bit words (192 bytes total) in **big-endian** byte order
///
/// # Side Effects
///
/// Transforms the state in-place through 24 rounds of the sponge permutation.
///
/// # Example from Test Vector (Table A.2)
///
/// ```rust
/// use bash::bash_f;
/// let mut state: [u64; 24] = [
///     0xB194BAC80A08F53B, 0x366D008E584A5DE4, 0x8504FA9D1BB6C7AC, 0x252E72C202FDCE0D,
///     0x5BE3D61217B96181, 0xFE6786AD716B890B, 0x5CB0C0FF33C356B8, 0x35C405AED8E07F99,
///     0xE12BDC1AE28257EC, 0x703FCCF095EE8DF1, 0xC1AB76389FE678CA, 0xF7C6F860D5BB9C4F,
///     0xF33C657B637C306A, 0xDD4EA7799EB23D31, 0x3E98B56E27D3BCCF, 0x591E181F4C5AB793,
///     0xE9DEE72C8F0C0FA6, 0x2DDB49F46F739647, 0x06075316ED247A37, 0x39CBA38303A98BF6,
///     0x92BD9B1CE5D14101, 0x5445FBC95E4D0EF2, 0x682080AA227D642F, 0x2687F93490405511,
/// ];
/// bash_f(&mut state);
/// assert_eq!(state[0], 0x8FE727775EA7F140);
/// // ... verify remaining words
/// ```
pub fn bash_f(state: &mut [u64; 24]) {
    state.iter_mut().for_each(|s| *s = s.swap_bytes());
    bash_f_internal(state);
    state.iter_mut().for_each(|s| *s = s.swap_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from Table A.1 of STB 34.101.77-2020.
    #[test]
    fn test_bash_s_table_a1() {
        let w0 = 0xB194BAC80A08F53B;
        let w1 = 0xE12BDC1AE28257EC;
        let w2 = 0xE9DEE72C8F0C0FA6;

        let (w0_out, w1_out, w2_out) = bash_s(w0, w1, w2, 8, 53, 14, 1);

        assert_eq!(w0_out, 0x479E76129979DC5F);
        assert_eq!(w1_out, 0x0F2B2C93ED128EDD);
        assert_eq!(w2_out, 0x41009B1B112DFEF3);
    }

    /// Test vector from Table A.2 of STB 34.101.77-2020.
    #[test]
    fn test_bash_f_table_a2() {
        let mut state: [u64; 24] = [
            0xB194BAC80A08F53B,
            0x366D008E584A5DE4,
            0x8504FA9D1BB6C7AC,
            0x252E72C202FDCE0D,
            0x5BE3D61217B96181,
            0xFE6786AD716B890B,
            0x5CB0C0FF33C356B8,
            0x35C405AED8E07F99,
            0xE12BDC1AE28257EC,
            0x703FCCF095EE8DF1,
            0xC1AB76389FE678CA,
            0xF7C6F860D5BB9C4F,
            0xF33C657B637C306A,
            0xDD4EA7799EB23D31,
            0x3E98B56E27D3BCCF,
            0x591E181F4C5AB793,
            0xE9DEE72C8F0C0FA6,
            0x2DDB49F46F739647,
            0x06075316ED247A37,
            0x39CBA38303A98BF6,
            0x92BD9B1CE5D14101,
            0x5445FBC95E4D0EF2,
            0x682080AA227D642F,
            0x2687F93490405511,
        ];

        bash_f(&mut state);

        let expected: [u64; 24] = [
            0x8FE727775EA7F140,
            0xB95BB6A200CBB28C,
            0x7F0809C0C0BC68B7,
            0xDC5AEDC841BD94E4,
            0x03630C301FC255DF,
            0x5B67DB53EF65E376,
            0xE8A4D797A6172F22,
            0x71BA48093173D329,
            0xC3502AC946767326,
            0xA2891971392D3F70,
            0x89959F5D61621238,
            0x655975E00E2132A0,
            0xD5018CEEDB17731C,
            0xCD88FC50151D37C0,
            0xD4A3359506AEDC2E,
            0x6109511E7703AFBB,
            0x014642348D8568AA,
            0x1A5D9868C4C7E6DF,
            0xA756B1690C7C2608,
            0xA2DC136F5997AB8F,
            0xBB3F4D9F033C87CA,
            0x6070E117F099C409,
            0x4972ACD9D976214B,
            0x7CED8E3F8B6E058E,
        ];

        for i in 0..24 {
            assert_eq!(
                state[i], expected[i],
                "Mismatch at S[{}]: got {:016X}, expected {:016X}",
                i, state[i], expected[i]
            );
        }
    }
}
