#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(keccak_backend = "simd", feature(portable_simd))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_upper_case_globals)]

//! ## Usage
//!
//! To disable loop unrolling (e.g. for constrained targets) use `no_unroll` feature.
//!
//! ```
//! // Test vectors are from KeccakCodePackage
//! let mut data = [0u64; 25];
//!
//! keccak::f1600(&mut data);
//! assert_eq!(data, [
//!     0xF1258F7940E1DDE7, 0x84D5CCF933C0478A, 0xD598261EA65AA9EE, 0xBD1547306F80494D,
//!     0x8B284E056253D057, 0xFF97A42D7F8E6FD4, 0x90FEE5A0A44647C4, 0x8C5BDA0CD6192E76,
//!     0xAD30A6F71B19059C, 0x30935AB7D08FFC64, 0xEB5AA93F2317D635, 0xA9A6E6260D712103,
//!     0x81A57C16DBCF555F, 0x43B831CD0347C826, 0x01F22F1A11A5569F, 0x05E5635A21D9AE61,
//!     0x64BEFEF28CC970F2, 0x613670957BC46611, 0xB87C5A554FD00ECB, 0x8C3EE88A1CCF32C8,
//!     0x940C7922AE3A2614, 0x1841F924A2C509E4, 0x16F53526E70465C2, 0x75F644E97F30A13B,
//!     0xEAF1FF7B5CECA249,
//! ]);
//!
//! keccak::f1600(&mut data);
//! assert_eq!(data, [
//!     0x2D5C954DF96ECB3C, 0x6A332CD07057B56D, 0x093D8D1270D76B6C, 0x8A20D9B25569D094,
//!     0x4F9C4F99E5E7F156, 0xF957B9A2DA65FB38, 0x85773DAE1275AF0D, 0xFAF4F247C3D810F7,
//!     0x1F1B9EE6F79A8759, 0xE4FECC0FEE98B425, 0x68CE61B6B9CE68A1, 0xDEEA66C4BA8F974F,
//!     0x33C43D836EAFB1F5, 0xE00654042719DBD9, 0x7CF8A9F009831265, 0xFD5449A6BF174743,
//!     0x97DDAD33D8994B40, 0x48EAD5FC5D0BE774, 0xE3B8C8EE55B7B03C, 0x91A0226E649E42E9,
//!     0x900E3129E7BADD7B, 0x202A9EC5FAA3CCE8, 0x5B3402464E1C3DB6, 0x609F4E62A44C1059,
//!     0x20D06CD26A8FBF5C,
//! ]);
//! ```

use core::{
    fmt::Debug,
    mem::size_of,
    ops::{BitAnd, BitAndAssign, BitXor, BitXorAssign, Not},
};

#[rustfmt::skip]
mod unroll;

// #[cfg(target_arch = "aarch64")]
// mod armv8;

#[cfg(target_arch = "aarch64")]
cpufeatures::new!(armv8_sha3_intrinsics, "sha3");

mod consts;

use consts::{PI, PLEN, RC, RHO};

/// A Keccak function which permutates `[u64; PLEN]`.
pub type KeccakFn = fn(&mut [u64; PLEN]);

/// Struct which handles switching between available backends.
#[derive(Debug, Copy, Clone)]
pub struct Backend {
    #[cfg(target_arch = "aarch64")]
    armv8_sha3: armv8_sha3_intrinsics::InitToken,
}

impl Default for Backend {
    #[inline]
    fn default() -> Self {
        Self {
            #[cfg(target_arch = "aarch64")]
            armv8_sha3: armv8_sha3_intrinsics::init(),
        }
    }
}

impl Backend {
    /// Create new Keccak backend.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute the provided backend closure with Keccak backend.
    pub fn with_backend(&self, f: impl BackendClosure) {
        #[cfg(target_arch = "aarch64")]
        if self.armv8_sha3.get() {
            // TODO: impl ARM backend
            return f.call_once::<SoftBakend>();
        }
        f.call_once::<SoftBakend>();
    }

    /// Execute the closure with `f1600` function.
    #[inline]
    pub fn with_f1600(&self, f: impl FnOnce(KeccakFn)) {
        struct Closure<F: FnOnce(KeccakFn)> {
            f: F,
        }

        impl<F: FnOnce(KeccakFn)> BackendClosure for Closure<F> {
            #[inline(always)]
            fn call_once<B: ParBackend>(self) {
                (self.f)(B::get_f1600());
            }
        }

        self.with_backend(Closure { f });
    }

    /// Execute the closure with `p1600` function with the specified number of rounds.
    ///
    /// # Panics
    /// If `ROUNDS` is equal to zero or bigger than 24.
    pub fn with_p1600<const ROUNDS: usize>(&self, f: impl FnOnce(KeccakFn)) {
        struct Closure<const ROUNDS: usize, F: FnOnce(KeccakFn)> {
            f: F,
        }

        impl<const ROUNDS: usize, F: FnOnce(KeccakFn)> BackendClosure for Closure<ROUNDS, F> {
            #[inline(always)]
            fn call_once<B: ParBackend>(self) {
                (self.f)(B::get_p1600::<ROUNDS>());
            }
        }

        self.with_backend(Closure::<ROUNDS, _> { f });
    }
}

/// Trait used to define a closure which operates over Keccak backends.
pub trait BackendClosure {
    /// Execute closure with the provided backend.
    fn call_once<B: ParBackend>(self);
}

/// Trait implemented by a Keccak backend
pub trait ParBackend {
    /// Degree of parallelism supported by the backend.
    const PAR_SIZE: usize;

    /// Get scalar `p1600` function with the specified number of rounds.
    fn get_p1600<const ROUNDS: usize>() -> KeccakFn;

    /// Apply `p1600` function with the specified number of rounds
    /// to the parallel state.
    ///
    /// # Panics
    /// - If `state.len()` is not equal to `Self::PAR_SIZE`.
    /// - If `ROUNDS` is equal to zero or bigger than 24.
    fn par_p1600<const ROUNDS: usize>(state: &mut [[u64; PLEN]]);

    /// Get scalar `f1600` function.
    #[inline]
    #[must_use]
    fn get_f1600() -> KeccakFn {
        Self::get_p1600::<{ u64::KECCAK_F_ROUND_COUNT }>()
    }

    /// Apply `f1600` function to the parallel state.
    ///
    /// # Panics
    /// If `state.len()` is not equal to `Self::PAR_SIZE`.
    #[inline]
    fn par_f1600(state: &mut [[u64; PLEN]]) {
        Self::par_p1600::<{ u64::KECCAK_F_ROUND_COUNT }>(state);
    }
}

struct SoftBakend;

impl ParBackend for SoftBakend {
    const PAR_SIZE: usize = 1;

    #[inline]
    fn get_p1600<const ROUNDS: usize>() -> KeccakFn {
        |s| p1600(s, ROUNDS)
    }

    #[inline]
    fn par_p1600<const ROUNDS: usize>(state: &mut [[u64; PLEN]]) {
        let [state] = state else {
            panic!("length of `state` is not equal to 1");
        };
        p1600(state, ROUNDS);
    }
}

/// Keccak is a permutation over an array of lanes which comprise the sponge
/// construction.
pub trait LaneSize:
    Copy
    + Clone
    + Debug
    + Default
    + PartialEq
    + BitAndAssign
    + BitAnd<Output = Self>
    + BitXorAssign
    + BitXor<Output = Self>
    + Not<Output = Self>
{
    /// Number of rounds of the Keccak-f permutation.
    const KECCAK_F_ROUND_COUNT: usize;

    /// Truncate function.
    fn truncate_rc(rc: u64) -> Self;

    /// Rotate left function.
    #[must_use]
    fn rotate_left(self, n: u32) -> Self;
}

macro_rules! impl_lanesize {
    ($type:ty, $round:expr, $truncate:expr) => {
        impl LaneSize for $type {
            const KECCAK_F_ROUND_COUNT: usize = $round;

            fn truncate_rc(rc: u64) -> Self {
                $truncate(rc)
            }

            fn rotate_left(self, n: u32) -> Self {
                self.rotate_left(n)
            }
        }
    };
}

impl_lanesize!(u8, 18, |rc: u64| { rc.to_le_bytes()[0] });
impl_lanesize!(u16, 20, |rc: u64| {
    let tmp = rc.to_le_bytes();
    #[allow(clippy::unwrap_used)]
    Self::from_le_bytes(tmp[..size_of::<Self>()].try_into().unwrap())
});
impl_lanesize!(u32, 22, |rc: u64| {
    let tmp = rc.to_le_bytes();
    #[allow(clippy::unwrap_used)]
    Self::from_le_bytes(tmp[..size_of::<Self>()].try_into().unwrap())
});
impl_lanesize!(u64, 24, |rc: u64| { rc });

macro_rules! impl_keccak {
    ($pname:ident, $fname:ident, $type:ty) => {
        /// Keccak-p sponge function
        pub fn $pname(state: &mut [$type; PLEN], round_count: usize) {
            keccak_p(state, round_count);
        }

        /// Keccak-f sponge function
        pub fn $fname(state: &mut [$type; PLEN]) {
            keccak_p(state, <$type>::KECCAK_F_ROUND_COUNT);
        }
    };
}

impl_keccak!(p200, f200, u8);
impl_keccak!(p400, f400, u16);
impl_keccak!(p800, f800, u32);
impl_keccak!(p1600, f1600, u64);

#[cfg(keccak_backend = "simd")]
/// SIMD implementations for Keccak-f1600 sponge function
pub mod simd {
    use crate::{LaneSize, PLEN, keccak_p};
    pub use core::simd::{u64x2, u64x4, u64x8};

    macro_rules! impl_lanesize_simd_u64xn {
        ($type:ty) => {
            impl LaneSize for $type {
                const KECCAK_F_ROUND_COUNT: usize = 24;

                fn truncate_rc(rc: u64) -> Self {
                    Self::splat(rc)
                }

                fn rotate_left(self, n: u32) -> Self {
                    self << Self::splat(n.into()) | self >> Self::splat((64 - n).into())
                }
            }
        };
    }

    impl_lanesize_simd_u64xn!(u64x2);
    impl_lanesize_simd_u64xn!(u64x4);
    impl_lanesize_simd_u64xn!(u64x8);

    impl_keccak!(p1600x2, f1600x2, u64x2);
    impl_keccak!(p1600x4, f1600x4, u64x4);
    impl_keccak!(p1600x8, f1600x8, u64x8);
}

/// Generic Keccak-p sponge function.
///
/// # Panics
/// If the round count is greater than `L::KECCAK_F_ROUND_COUNT`.
#[allow(unused_assignments)]
pub fn keccak_p<L: LaneSize>(state: &mut [L; PLEN], round_count: usize) {
    assert!(
        round_count <= L::KECCAK_F_ROUND_COUNT,
        "A round_count greater than KECCAK_F_ROUND_COUNT is not supported!"
    );

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=25
    // "the rounds of KECCAK-p[b, nr] match the last rounds of KECCAK-f[b]"
    let round_consts = &RC[(L::KECCAK_F_ROUND_COUNT - round_count)..L::KECCAK_F_ROUND_COUNT];

    // not unrolling this loop results in a much smaller function, plus
    // it positively influences performance due to the smaller load on I-cache
    for &rc in round_consts {
        let mut array = [L::default(); 5];

        // Theta
        unroll5!(x, {
            unroll5!(y, {
                array[x] ^= state[5 * y + x];
            });
        });

        unroll5!(x, {
            let t1 = array[(x + 4) % 5];
            let t2 = array[(x + 1) % 5].rotate_left(1);
            unroll5!(y, {
                state[5 * y + x] ^= t1 ^ t2;
            });
        });

        // Rho and pi
        let mut last = state[1];
        unroll24!(x, {
            array[0] = state[PI[x]];
            state[PI[x]] = last.rotate_left(RHO[x]);
            last = array[0];
        });

        // Chi
        unroll5!(y_step, {
            let y = 5 * y_step;

            array.copy_from_slice(&state[y..][..5]);

            unroll5!(x, {
                let t1 = !array[(x + 1) % 5];
                let t2 = array[(x + 2) % 5];
                state[y + x] = array[x] ^ (t1 & t2);
            });
        });

        // Iota
        state[0] ^= L::truncate_rc(rc);
    }
}

#[cfg(test)]
mod tests {
    use crate::{Backend, LaneSize, PLEN, keccak_p};

    fn keccak_f<L: LaneSize>(state_first: [L; PLEN], state_second: [L; PLEN]) {
        let mut state = [L::default(); PLEN];

        keccak_p(&mut state, L::KECCAK_F_ROUND_COUNT);
        assert_eq!(state, state_first);

        keccak_p(&mut state, L::KECCAK_F_ROUND_COUNT);
        assert_eq!(state, state_second);
    }

    #[test]
    fn keccak_f200() {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-200-IntermediateValues.txt
        let state_first = [
            0x3C, 0x28, 0x26, 0x84, 0x1C, 0xB3, 0x5C, 0x17, 0x1E, 0xAA, 0xE9, 0xB8, 0x11, 0x13,
            0x4C, 0xEA, 0xA3, 0x85, 0x2C, 0x69, 0xD2, 0xC5, 0xAB, 0xAF, 0xEA,
        ];
        let state_second = [
            0x1B, 0xEF, 0x68, 0x94, 0x92, 0xA8, 0xA5, 0x43, 0xA5, 0x99, 0x9F, 0xDB, 0x83, 0x4E,
            0x31, 0x66, 0xA1, 0x4B, 0xE8, 0x27, 0xD9, 0x50, 0x40, 0x47, 0x9E,
        ];

        keccak_f::<u8>(state_first, state_second);
    }

    #[test]
    fn keccak_f400() {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-400-IntermediateValues.txt
        let state_first = [
            0x09F5, 0x40AC, 0x0FA9, 0x14F5, 0xE89F, 0xECA0, 0x5BD1, 0x7870, 0xEFF0, 0xBF8F, 0x0337,
            0x6052, 0xDC75, 0x0EC9, 0xE776, 0x5246, 0x59A1, 0x5D81, 0x6D95, 0x6E14, 0x633E, 0x58EE,
            0x71FF, 0x714C, 0xB38E,
        ];
        let state_second = [
            0xE537, 0xD5D6, 0xDBE7, 0xAAF3, 0x9BC7, 0xCA7D, 0x86B2, 0xFDEC, 0x692C, 0x4E5B, 0x67B1,
            0x15AD, 0xA7F7, 0xA66F, 0x67FF, 0x3F8A, 0x2F99, 0xE2C2, 0x656B, 0x5F31, 0x5BA6, 0xCA29,
            0xC224, 0xB85C, 0x097C,
        ];

        keccak_f::<u16>(state_first, state_second);
    }

    #[test]
    fn keccak_f800() {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt
        let state_first = [
            0xE531D45D, 0xF404C6FB, 0x23A0BF99, 0xF1F8452F, 0x51FFD042, 0xE539F578, 0xF00B80A7,
            0xAF973664, 0xBF5AF34C, 0x227A2424, 0x88172715, 0x9F685884, 0xB15CD054, 0x1BF4FC0E,
            0x6166FA91, 0x1A9E599A, 0xA3970A1F, 0xAB659687, 0xAFAB8D68, 0xE74B1015, 0x34001A98,
            0x4119EFF3, 0x930A0E76, 0x87B28070, 0x11EFE996,
        ];
        let state_second = [
            0x75BF2D0D, 0x9B610E89, 0xC826AF40, 0x64CD84AB, 0xF905BDD6, 0xBC832835, 0x5F8001B9,
            0x15662CCE, 0x8E38C95E, 0x701FE543, 0x1B544380, 0x89ACDEFF, 0x51EDB5DE, 0x0E9702D9,
            0x6C19AA16, 0xA2913EEE, 0x60754E9A, 0x9819063C, 0xF4709254, 0xD09F9084, 0x772DA259,
            0x1DB35DF7, 0x5AA60162, 0x358825D5, 0xB3783BAB,
        ];

        keccak_f::<u32>(state_first, state_second);
    }

    #[test]
    fn keccak_f1600() {
        // Test vectors are copied from XKCP (eXtended Keccak Code Package)
        // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
        let state_first = [
            0xF1258F7940E1DDE7,
            0x84D5CCF933C0478A,
            0xD598261EA65AA9EE,
            0xBD1547306F80494D,
            0x8B284E056253D057,
            0xFF97A42D7F8E6FD4,
            0x90FEE5A0A44647C4,
            0x8C5BDA0CD6192E76,
            0xAD30A6F71B19059C,
            0x30935AB7D08FFC64,
            0xEB5AA93F2317D635,
            0xA9A6E6260D712103,
            0x81A57C16DBCF555F,
            0x43B831CD0347C826,
            0x01F22F1A11A5569F,
            0x05E5635A21D9AE61,
            0x64BEFEF28CC970F2,
            0x613670957BC46611,
            0xB87C5A554FD00ECB,
            0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614,
            0x1841F924A2C509E4,
            0x16F53526E70465C2,
            0x75F644E97F30A13B,
            0xEAF1FF7B5CECA249,
        ];
        let state_second = [
            0x2D5C954DF96ECB3C,
            0x6A332CD07057B56D,
            0x093D8D1270D76B6C,
            0x8A20D9B25569D094,
            0x4F9C4F99E5E7F156,
            0xF957B9A2DA65FB38,
            0x85773DAE1275AF0D,
            0xFAF4F247C3D810F7,
            0x1F1B9EE6F79A8759,
            0xE4FECC0FEE98B425,
            0x68CE61B6B9CE68A1,
            0xDEEA66C4BA8F974F,
            0x33C43D836EAFB1F5,
            0xE00654042719DBD9,
            0x7CF8A9F009831265,
            0xFD5449A6BF174743,
            0x97DDAD33D8994B40,
            0x48EAD5FC5D0BE774,
            0xE3B8C8EE55B7B03C,
            0x91A0226E649E42E9,
            0x900E3129E7BADD7B,
            0x202A9EC5FAA3CCE8,
            0x5B3402464E1C3DB6,
            0x609F4E62A44C1059,
            0x20D06CD26A8FBF5C,
        ];

        keccak_f::<u64>(state_first, state_second);

        Backend::new().with_f1600(|f1600| {
            let mut buf = state_first;
            f1600(&mut buf);
            assert_eq!(buf, state_second);
        });

        Backend::new().with_p1600::<24>(|p1600_24| {
            let mut buf = state_first;
            p1600_24(&mut buf);
            assert_eq!(buf, state_second);
        });
    }

    #[cfg(keccak_backend = "simd")]
    mod simd {
        use super::keccak_f;
        use core::simd::{u64x2, u64x4, u64x8};

        macro_rules! impl_keccak_f1600xn {
            ($name:ident, $type:ty) => {
                #[test]
                fn $name() {
                    // Test vectors are copied from XKCP (eXtended Keccak Code Package)
                    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
                    let state_first = [
                        <$type>::splat(0xF1258F7940E1DDE7),
                        <$type>::splat(0x84D5CCF933C0478A),
                        <$type>::splat(0xD598261EA65AA9EE),
                        <$type>::splat(0xBD1547306F80494D),
                        <$type>::splat(0x8B284E056253D057),
                        <$type>::splat(0xFF97A42D7F8E6FD4),
                        <$type>::splat(0x90FEE5A0A44647C4),
                        <$type>::splat(0x8C5BDA0CD6192E76),
                        <$type>::splat(0xAD30A6F71B19059C),
                        <$type>::splat(0x30935AB7D08FFC64),
                        <$type>::splat(0xEB5AA93F2317D635),
                        <$type>::splat(0xA9A6E6260D712103),
                        <$type>::splat(0x81A57C16DBCF555F),
                        <$type>::splat(0x43B831CD0347C826),
                        <$type>::splat(0x01F22F1A11A5569F),
                        <$type>::splat(0x05E5635A21D9AE61),
                        <$type>::splat(0x64BEFEF28CC970F2),
                        <$type>::splat(0x613670957BC46611),
                        <$type>::splat(0xB87C5A554FD00ECB),
                        <$type>::splat(0x8C3EE88A1CCF32C8),
                        <$type>::splat(0x940C7922AE3A2614),
                        <$type>::splat(0x1841F924A2C509E4),
                        <$type>::splat(0x16F53526E70465C2),
                        <$type>::splat(0x75F644E97F30A13B),
                        <$type>::splat(0xEAF1FF7B5CECA249),
                    ];
                    let state_second = [
                        <$type>::splat(0x2D5C954DF96ECB3C),
                        <$type>::splat(0x6A332CD07057B56D),
                        <$type>::splat(0x093D8D1270D76B6C),
                        <$type>::splat(0x8A20D9B25569D094),
                        <$type>::splat(0x4F9C4F99E5E7F156),
                        <$type>::splat(0xF957B9A2DA65FB38),
                        <$type>::splat(0x85773DAE1275AF0D),
                        <$type>::splat(0xFAF4F247C3D810F7),
                        <$type>::splat(0x1F1B9EE6F79A8759),
                        <$type>::splat(0xE4FECC0FEE98B425),
                        <$type>::splat(0x68CE61B6B9CE68A1),
                        <$type>::splat(0xDEEA66C4BA8F974F),
                        <$type>::splat(0x33C43D836EAFB1F5),
                        <$type>::splat(0xE00654042719DBD9),
                        <$type>::splat(0x7CF8A9F009831265),
                        <$type>::splat(0xFD5449A6BF174743),
                        <$type>::splat(0x97DDAD33D8994B40),
                        <$type>::splat(0x48EAD5FC5D0BE774),
                        <$type>::splat(0xE3B8C8EE55B7B03C),
                        <$type>::splat(0x91A0226E649E42E9),
                        <$type>::splat(0x900E3129E7BADD7B),
                        <$type>::splat(0x202A9EC5FAA3CCE8),
                        <$type>::splat(0x5B3402464E1C3DB6),
                        <$type>::splat(0x609F4E62A44C1059),
                        <$type>::splat(0x20D06CD26A8FBF5C),
                    ];

                    keccak_f::<$type>(state_first, state_second);
                }
            };
        }

        impl_keccak_f1600xn!(keccak_f1600x2, u64x2);
        impl_keccak_f1600xn!(keccak_f1600x4, u64x4);
        impl_keccak_f1600xn!(keccak_f1600x8, u64x8);
    }
}
