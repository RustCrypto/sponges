use crate::PLEN;

/// Keccak-p1600 with AVX2.
#[target_feature(enable = "avx2")]
pub unsafe fn p1600_avx2_sha3_asm(state: &mut [u64; PLEN], round_count: usize) {
    assert!(
        matches!(round_count, 1..=24),
        "invalid round count (must be 1-24): {}",
        round_count
    );

    // SAFETY:
    // - caller is responsible for ensuring that the target CPU supports AVX2
    // - `round_count` is ensured to be in the range `1..=24` above
    // - `state` is valid, aligned, and mutably borrowed as a Rust reference above
    unsafe {
        core::arch::asm!("
            vpshufd ymm13,ymm2,0x4e
            vpxor  ymm12,ymm5,ymm3
            vpxor  ymm9,ymm4,ymm6
            vpxor  ymm12,ymm12,ymm1
            vpxor  ymm12,ymm12,ymm9
            vpermq ymm11,ymm12,0x93
            vpxor  ymm13,ymm13,ymm2
            vpermq ymm7,ymm13,0x4e
            vpsrlq ymm8,ymm12,0x3f
            vpaddq ymm9,ymm12,ymm12
            vpor   ymm8,ymm8,ymm9
            vpermq ymm15,ymm8,0x39
            vpxor  ymm14,ymm8,ymm11
            vpermq ymm14,ymm14,0x0
            vpxor  ymm13,ymm13,ymm0
            vpxor  ymm13,ymm13,ymm7
            vpsrlq ymm7,ymm13,0x3f
            vpaddq ymm8,ymm13,ymm13
            vpor   ymm8,ymm8,ymm7
            vpxor  ymm2,ymm2,ymm14
            vpxor  ymm0,ymm0,ymm14
            vpblendd ymm15,ymm15,ymm8,0xc0
            vpblendd ymm11,ymm11,ymm13,0x3
            vpxor  ymm15,ymm15,ymm11
            vpsllvq ymm10,ymm2,YMMWORD PTR [r8-0x60]
            vpsrlvq ymm2,ymm2,YMMWORD PTR [r9-0x60]
            vpor   ymm2,ymm2,ymm10
            vpxor  ymm3,ymm3,ymm15
            vpsllvq ymm11,ymm3,YMMWORD PTR [r8-0x20]
            vpsrlvq ymm3,ymm3,YMMWORD PTR [r9-0x20]
            vpor   ymm3,ymm3,ymm11
            vpxor  ymm4,ymm4,ymm15
            vpsllvq ymm12,ymm4,YMMWORD PTR [r8]
            vpsrlvq ymm4,ymm4,YMMWORD PTR [r9]
            vpor   ymm4,ymm4,ymm12
            vpxor  ymm5,ymm5,ymm15
            vpsllvq ymm13,ymm5,YMMWORD PTR [r8+0x20]
            vpsrlvq ymm5,ymm5,YMMWORD PTR [r9+0x20]
            vpor   ymm5,ymm5,ymm13
            vpxor  ymm6,ymm6,ymm15
            vpermq ymm10,ymm2,0x8d
            vpermq ymm11,ymm3,0x8d
            vpsllvq ymm14,ymm6,YMMWORD PTR [r8+0x40]
            vpsrlvq ymm8,ymm6,YMMWORD PTR [r9+0x40]
            vpor   ymm8,ymm8,ymm14
            vpxor  ymm1,ymm1,ymm15
            vpermq ymm12,ymm4,0x1b
            vpermq ymm13,ymm5,0x72
            vpsllvq ymm15,ymm1,YMMWORD PTR [r8-0x40]
            vpsrlvq ymm9,ymm1,YMMWORD PTR [r9-0x40]
            vpor   ymm9,ymm9,ymm15
            vpsrldq ymm14,ymm8,0x8
            vpandn ymm7,ymm8,ymm14
            vpblendd ymm3,ymm9,ymm13,0xc
            vpblendd ymm15,ymm11,ymm9,0xc
            vpblendd ymm5,ymm10,ymm11,0xc
            vpblendd ymm14,ymm9,ymm10,0xc
            vpblendd ymm3,ymm3,ymm11,0x30
            vpblendd ymm15,ymm15,ymm12,0x30
            vpblendd ymm5,ymm5,ymm9,0x30
            vpblendd ymm14,ymm14,ymm13,0x30
            vpblendd ymm3,ymm3,ymm12,0xc0
            vpblendd ymm15,ymm15,ymm13,0xc0
            vpblendd ymm5,ymm5,ymm13,0xc0
            vpblendd ymm14,ymm14,ymm11,0xc0
            vpandn ymm3,ymm3,ymm15
            vpandn ymm5,ymm5,ymm14
            vpblendd ymm6,ymm12,ymm9,0xc
            vpblendd ymm15,ymm10,ymm12,0xc
            vpxor  ymm3,ymm3,ymm10
            vpblendd ymm6,ymm6,ymm10,0x30
            vpblendd ymm15,ymm15,ymm11,0x30
            vpxor  ymm5,ymm5,ymm12
            vpblendd ymm6,ymm6,ymm11,0xc0
            vpblendd ymm15,ymm15,ymm9,0xc0
            vpandn ymm6,ymm6,ymm15
            vpxor  ymm6,ymm6,ymm13
            vpermq ymm4,ymm8,0x1e
            vpblendd ymm15,ymm4,ymm0,0x30
            vpermq ymm1,ymm8,0x39
            vpblendd ymm1,ymm1,ymm0,0xc0
            vpandn ymm1,ymm1,ymm15
            vpblendd ymm2,ymm11,ymm12,0xc
            vpblendd ymm14,ymm13,ymm11,0xc
            vpblendd ymm2,ymm2,ymm13,0x30
            vpblendd ymm14,ymm14,ymm10,0x30
            vpblendd ymm2,ymm2,ymm10,0xc0
            vpblendd ymm14,ymm14,ymm12,0xc0
            vpandn ymm2,ymm2,ymm14
            vpxor  ymm2,ymm2,ymm9
            vpermq ymm7,ymm7,0x0
            vpermq ymm3,ymm3,0x1b
            vpermq ymm5,ymm5,0x8d
            vpermq ymm6,ymm6,0x72
            vpblendd ymm4,ymm13,ymm10,0xc
            vpblendd ymm14,ymm12,ymm13,0xc
            vpblendd ymm4,ymm4,ymm12,0x30
            vpblendd ymm14,ymm14,ymm9,0x30
            vpblendd ymm4,ymm4,ymm9,0xc0
            vpblendd ymm14,ymm14,ymm10,0xc0
            vpandn ymm4,ymm4,ymm14
            vpxor  ymm0,ymm0,ymm7
            vpxor  ymm1,ymm1,ymm8
            vpxor  ymm4,ymm4,ymm11
            vpxor  ymm0,ymm0,YMMWORD PTR [r10]
            lea    r10,[r10+0x20]
        ",
            inout("x0") state.as_mut_ptr() => _,
            inout("x1") crate::RC[24-round_count..].as_ptr() => _,
            inout("x8") round_count => _,
            clobber_abi("C"),
            options(nostack)
        );
    }
}

#[cfg(all(test, target_feature = "sha3"))]
#[allow(clippy::undocumented_unsafe_blocks)]
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
        unsafe { p1600_armv8_sha3_asm(&mut state, 24) };
        assert_eq!(state, state_first);
        unsafe { p1600_armv8_sha3_asm(&mut state, 24) };
        assert_eq!(state, state_second);
    }
}
