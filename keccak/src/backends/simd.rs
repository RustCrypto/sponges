/// Backend implementation using the portable SIMD API.
use super::soft::{LaneSize, keccak_p};
use crate::types::{Fn1600, ParFn1600};
use core::array;
use hybrid_array::{Array, typenum};

#[cfg(keccak_backend = "simd128")]
use core::simd::u64x2 as u64xN;
#[cfg(keccak_backend = "simd256")]
use core::simd::u64x4 as u64xN;
#[cfg(keccak_backend = "simd512")]
use core::simd::u64x8 as u64xN;

impl LaneSize for u64xN {
    const KECCAK_F_ROUND_COUNT: usize = crate::consts::F1600_ROUNDS;

    fn truncate_rc(rc: u64) -> Self {
        Self::splat(rc)
    }

    fn rotate_left(self, n: u32) -> Self {
        self << Self::splat(n.into()) | self >> Self::splat((64 - n).into())
    }
}

/// Portable SIMD backend
pub(crate) struct Backend;

impl super::Backend for Backend {
    #[cfg(all(feature = "parallel", keccak_backend = "simd128"))]
    type ParSize1600 = typenum::U2;
    #[cfg(all(feature = "parallel", keccak_backend = "simd256"))]
    type ParSize1600 = typenum::U4;
    #[cfg(all(feature = "parallel", keccak_backend = "simd512"))]
    type ParSize1600 = typenum::U8;

    #[inline]
    fn get_p1600<const ROUNDS: usize>() -> Fn1600 {
        keccak_p::<u64, ROUNDS>
    }

    #[cfg(feature = "parallel")]
    #[inline]
    fn get_par_p1600<const ROUNDS: usize>() -> ParFn1600<Self> {
        fn transpose<const N: usize, const M: usize>(arr: &[[u64; N]; M]) -> [[u64; M]; N] {
            array::from_fn(|i| array::from_fn(|j| arr[j][i]))
        }

        |Array(state)| {
            let mut simd_state = transpose(state).map(u64xN::from_array);
            keccak_p::<_, ROUNDS>(&mut simd_state);
            *state = transpose(&simd_state.map(u64xN::to_array));
        }
    }
}
