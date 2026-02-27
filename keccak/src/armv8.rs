#![allow(unsafe_op_in_unsafe_fn)]

use crate::{PLEN, RC};
use core::{arch::aarch64::*, array};

/// Keccak-p1600 on ARMv8.4-A with `FEAT_SHA3`.
///
/// See p. K12.2.2  p. 11,749 of the ARM Reference manual.
/// Adapted from the Keccak-f1600 implementation in the XKCP/K12.
/// see <https://github.com/XKCP/K12/blob/df6a21e6d1f34c1aa36e8d702540899c97dba5a0/lib/ARMv8Asha3/KeccakP-1600-ARMv8Asha3.S#L69>
#[target_feature(enable = "sha3")]
pub unsafe fn p1600_armv8_sha3(state: &mut [u64; PLEN], round_count: usize) {
    let mut s = [*state, Default::default()];
    // SAFETY: both functions have the same safety invariants, namely they require the `sha3`
    // target feature is available, and the caller is responsible for ensuring support
    unsafe { p1600_armv8_sha3_times2(&mut s, round_count) };
    *state = s[0];
}

/// Keccak-p1600 on ARMv8.4-A with `FEAT_SHA3` with support for 2 parallel states.
///
/// See p. K12.2.2  p. 11,749 of the ARM Reference manual.
/// Adapted from the Keccak-f1600 implementation in the XKCP/K12.
///
/// <https://github.com/XKCP/K12/blob/df6a21e/lib/ARMv8Asha3/KeccakP-1600-ARMv8Asha3.S#L69>
#[target_feature(enable = "sha3")]
pub unsafe fn p1600_armv8_sha3_times2(state: &mut [[u64; PLEN]; 2], round_count: usize) {
    assert!(
        matches!(round_count, 1..=24),
        "invalid round count (must be 1-24): {}",
        round_count
    );

    let mut s: [uint64x2_t; PLEN] =
        array::from_fn(|i| vcombine_u64(vcreate_u64(state[0][i]), vcreate_u64(state[1][i])));

    for &rc in &RC[(24 - round_count)..] {
        let (d0, d1, d2, d3, d4) = theta(&s);
        let t = rho_pi(&s, d0, d1, d2, d3, d4);
        s = chi_iota(&t, rc);
    }

    for i in 0..PLEN {
        state[0][i] = vgetq_lane_u64::<0>(s[i]);
        state[1][i] = vgetq_lane_u64::<1>(s[i]);
    }
}

#[target_feature(enable = "sha3")]
unsafe fn theta(
    s: &[uint64x2_t; 25],
) -> (uint64x2_t, uint64x2_t, uint64x2_t, uint64x2_t, uint64x2_t) {
    let c0 = veor3q_u64(s[0], s[5], veor3q_u64(s[10], s[15], s[20]));
    let c1 = veor3q_u64(s[1], s[6], veor3q_u64(s[11], s[16], s[21]));
    let c2 = veor3q_u64(s[2], s[7], veor3q_u64(s[12], s[17], s[22]));
    let c3 = veor3q_u64(s[3], s[8], veor3q_u64(s[13], s[18], s[23]));
    let c4 = veor3q_u64(s[4], s[9], veor3q_u64(s[14], s[19], s[24]));

    let d0 = vrax1q_u64(c4, c1);
    let d1 = vrax1q_u64(c0, c2);
    let d2 = vrax1q_u64(c1, c3);
    let d3 = vrax1q_u64(c2, c4);
    let d4 = vrax1q_u64(c3, c0);

    (d0, d1, d2, d3, d4)
}

#[target_feature(enable = "sha3")]
unsafe fn rho_pi(
    s: &[uint64x2_t; 25],
    d0: uint64x2_t,
    d1: uint64x2_t,
    d2: uint64x2_t,
    d3: uint64x2_t,
    d4: uint64x2_t,
) -> [uint64x2_t; 25] {
    let v0 = veorq_u64(s[0], d0);
    let v25 = vxarq_u64::<63>(s[1], d1);
    let v1 = vxarq_u64::<20>(s[6], d1);
    let v6 = vxarq_u64::<44>(s[9], d4);
    let v9 = vxarq_u64::<3>(s[22], d2);
    let v22 = vxarq_u64::<25>(s[14], d4);
    let v14 = vxarq_u64::<46>(s[20], d0);
    let v26 = vxarq_u64::<2>(s[2], d2);
    let v2 = vxarq_u64::<21>(s[12], d2);
    let v12 = vxarq_u64::<39>(s[13], d3);
    let v13 = vxarq_u64::<56>(s[19], d4);
    let v19 = vxarq_u64::<8>(s[23], d3);
    let v23 = vxarq_u64::<23>(s[15], d0);
    let v15 = vxarq_u64::<37>(s[4], d4);
    let v28 = vxarq_u64::<50>(s[24], d4);
    let v24 = vxarq_u64::<62>(s[21], d1);
    let v8 = vxarq_u64::<9>(s[8], d3);
    let v4 = vxarq_u64::<19>(s[16], d1);
    let v16 = vxarq_u64::<28>(s[5], d0);
    let v5 = vxarq_u64::<36>(s[3], d3);
    let v27 = vxarq_u64::<43>(s[18], d3);
    let v3 = vxarq_u64::<49>(s[17], d2);
    let v30 = vxarq_u64::<54>(s[11], d1);
    let v31 = vxarq_u64::<58>(s[7], d2);
    let v29 = vxarq_u64::<61>(s[10], d0);
    [
        v0, v25, v26, v5, v15, v16, v1, v31, v8, v6, v29, v30, v2, v12, v22, v23, v4, v3, v27, v13,
        v14, v24, v9, v19, v28,
    ]
}

#[target_feature(enable = "sha3")]
unsafe fn chi_iota(t: &[uint64x2_t; 25], rc: u64) -> [uint64x2_t; 25] {
    let rc_v = vdupq_n_u64(rc);
    let v20 = vbcaxq_u64(t[2], t[14], t[8]);
    let v21 = vbcaxq_u64(t[8], t[15], t[14]);
    let v22 = vbcaxq_u64(t[14], t[21], t[15]);
    let v23 = vbcaxq_u64(t[15], t[2], t[21]);
    let v24 = vbcaxq_u64(t[21], t[8], t[2]);
    let v17 = vbcaxq_u64(t[11], t[23], t[17]);
    let v18 = vbcaxq_u64(t[17], t[4], t[23]);
    let v19 = vbcaxq_u64(t[23], t[5], t[4]);
    let v15 = vbcaxq_u64(t[4], t[11], t[5]);
    let v16 = vbcaxq_u64(t[5], t[17], t[11]);
    let v10 = vbcaxq_u64(t[1], t[13], t[7]);
    let v11 = vbcaxq_u64(t[7], t[19], t[13]);
    let v12 = vbcaxq_u64(t[13], t[20], t[19]);
    let v13 = vbcaxq_u64(t[19], t[1], t[20]);
    let v14 = vbcaxq_u64(t[20], t[7], t[1]);
    let v7 = vbcaxq_u64(t[10], t[22], t[16]);
    let v8 = vbcaxq_u64(t[16], t[3], t[22]);
    let v9 = vbcaxq_u64(t[22], t[9], t[3]);
    let v5 = vbcaxq_u64(t[3], t[10], t[9]);
    let v6 = vbcaxq_u64(t[9], t[16], t[10]);
    let v3 = vbcaxq_u64(t[18], t[0], t[24]);
    let v4 = vbcaxq_u64(t[24], t[6], t[0]);
    let v0 = vbcaxq_u64(t[0], t[12], t[6]);
    let v1 = vbcaxq_u64(t[6], t[18], t[12]);
    let v2 = vbcaxq_u64(t[12], t[24], t[18]);
    let v0_iota = veorq_u64(v0, rc_v);
    [
        v0_iota, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
        v19, v20, v21, v22, v23, v24,
    ]
}

#[cfg(all(test, target_feature = "sha3"))]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_f1600() {
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

        let mut state = [0u64; 25];
        unsafe { p1600_armv8_sha3(&mut state, 24) };
        assert_eq!(state, state_first);
        unsafe { p1600_armv8_sha3(&mut state, 24) };
        assert_eq!(state, state_second);
    }
}
