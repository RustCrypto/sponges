// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::mem::size_of;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Produce mask for padding.
#[inline(always)]
pub const fn pad(n: usize) -> u64 {
    0x80_u64 << (56 - 8 * n)
}

/// Compute round constant
#[inline(always)]
const fn round_constant(round: u64) -> u64 {
    ((0xfu64 - round) << 4) | round
}

/// The state of Ascon's permutation.
///
/// The permutation operates on a state of 320 bits represented as 5 64 bit words.
#[derive(Clone, Debug, Default)]
pub struct State {
    x: [u64; 5],
}

/// Ascon's round function
const fn round(x: [u64; 5], c: u64) -> [u64; 5] {
    // S-box layer
    let x0 = x[0] ^ x[4];
    let x2 = x[2] ^ x[1] ^ c; // with round constant
    let x4 = x[4] ^ x[3];

    let tx0 = x0 ^ (!x[1] & x2);
    let tx1 = x[1] ^ (!x2 & x[3]);
    let tx2 = x2 ^ (!x[3] & x4);
    let tx3 = x[3] ^ (!x4 & x0);
    let tx4 = x4 ^ (!x0 & x[1]);
    let tx1 = tx1 ^ tx0;
    let tx3 = tx3 ^ tx2;
    let tx0 = tx0 ^ tx4;

    // linear layer
    let x0 = tx0 ^ tx0.rotate_right(9);
    let x1 = tx1 ^ tx1.rotate_right(22);
    let x2 = tx2 ^ tx2.rotate_right(5);
    let x3 = tx3 ^ tx3.rotate_right(7);
    let x4 = tx4 ^ tx4.rotate_right(34);
    [
        tx0 ^ x0.rotate_right(19),
        tx1 ^ x1.rotate_right(39),
        !(tx2 ^ x2.rotate_right(1)),
        tx3 ^ x3.rotate_right(10),
        tx4 ^ x4.rotate_right(7),
    ]
}

impl State {
    /// Instantiate new state from the given values.
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x: [x0, x1, x2, x3, x4],
        }
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        // We could in theory iter().fold() over an array of round constants,
        // but the compiler produces better results when optimizing this chain
        // of round function calls.
        self.x = round(
            round(
                round(
                    round(
                        round(
                            round(
                                round(
                                    round(
                                        round(round(round(round(self.x, 0xf0), 0xe1), 0xd2), 0xc3),
                                        0xb4,
                                    ),
                                    0xa5,
                                ),
                                0x96,
                            ),
                            0x87,
                        ),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        self.x = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ]
        .into_iter()
        .fold(self.x, round);
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = round(
            round(
                round(
                    round(
                        round(round(round(round(self.x, 0xb4), 0xa5), 0x96), 0x87),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self.x, round);
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(&mut self) {
        self.x = round(
            round(
                round(round(round(round(self.x, 0x96), 0x87), 0x78), 0x69),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(&mut self) {
        self.x = [0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self.x, round);
    }

    /// Perform permutation with 1 round
    pub fn permute_1(&mut self) {
        self.x = round(self.x, 0x4b);
    }

    /// Perform a given number (up to 12) of permutations
    ///
    /// Panics (in debug mode) if `rounds` is larger than 12.
    pub fn permute_n(&mut self, rounds: usize) {
        debug_assert!(rounds <= 12);

        let start = 12 - rounds;
        self.x = (start..12).fold(self.x, |x, round_index| {
            round(x, round_constant(round_index as u64))
        });
    }

    /// Convert state to bytes.
    pub fn as_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; size_of::<u64>() * 5];
        for (dst, src) in bytes.chunks_exact_mut(size_of::<u64>()).zip(self.x) {
            dst.copy_from_slice(&u64::to_be_bytes(src));
        }
        bytes
    }
}

impl core::ops::Index<usize> for State {
    type Output = u64;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.x[index]
    }
}

impl core::ops::IndexMut<usize> for State {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.x[index]
    }
}

impl TryFrom<&[u64]> for State {
    type Error = ();

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        match value.len() {
            5 => Ok(Self::new(value[0], value[1], value[2], value[3], value[4])),
            _ => Err(()),
        }
    }
}

impl From<&[u64; 5]> for State {
    fn from(value: &[u64; 5]) -> Self {
        Self { x: *value }
    }
}

impl TryFrom<&[u8]> for State {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<u64>() * 5 {
            return Err(());
        }

        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        Ok(state)
    }
}

impl From<&[u8; size_of::<u64>() * 5]> for State {
    fn from(value: &[u8; size_of::<u64>() * 5]) -> Self {
        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        state
    }
}

impl AsRef<[u64]> for State {
    fn as_ref(&self) -> &[u64] {
        &self.x
    }
}

#[cfg(feature = "zeroize")]
impl Drop for State {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for State {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_0to7() {
        assert_eq!(pad(0), 0x8000000000000000);
        assert_eq!(pad(1), 0x80000000000000);
        assert_eq!(pad(2), 0x800000000000);
        assert_eq!(pad(3), 0x8000000000);
        assert_eq!(pad(4), 0x80000000);
        assert_eq!(pad(5), 0x800000);
        assert_eq!(pad(6), 0x8000);
        assert_eq!(pad(7), 0x80);
    }

    #[test]
    fn round_constants() {
        assert_eq!(round_constant(0), 0xf0);
        assert_eq!(round_constant(1), 0xe1);
        assert_eq!(round_constant(2), 0xd2);
        assert_eq!(round_constant(3), 0xc3);
        assert_eq!(round_constant(4), 0xb4);
        assert_eq!(round_constant(5), 0xa5);
        assert_eq!(round_constant(6), 0x96);
        assert_eq!(round_constant(7), 0x87);
        assert_eq!(round_constant(8), 0x78);
        assert_eq!(round_constant(9), 0x69);
        assert_eq!(round_constant(10), 0x5a);
        assert_eq!(round_constant(11), 0x4b);
    }

    #[test]
    fn one_round() {
        let state = round(
            [
                0x0123456789abcdef,
                0x23456789abcdef01,
                0x456789abcdef0123,
                0x6789abcdef012345,
                0x89abcde01234567f,
            ],
            0x1f,
        );
        assert_eq!(
            state,
            [
                0x3c1748c9be2892ce,
                0x5eafb305cd26164f,
                0xf9470254bb3a4213,
                0xf0428daf0c5d3948,
                0x281375af0b294899
            ]
        );
    }

    #[test]
    fn state_permute_12() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_12();
        assert_eq!(state[0], 0x206416dfc624bb14);
        assert_eq!(state[1], 0x1b0c47a601058aab);
        assert_eq!(state[2], 0x8934cfc93814cddd);
        assert_eq!(state[3], 0xa9738d287a748e4b);
        assert_eq!(state[4], 0xddd934f058afc7e1);
    }

    #[test]
    fn state_permute_6() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_6();
        assert_eq!(state[0], 0xc27b505c635eb07f);
        assert_eq!(state[1], 0xd388f5d2a72046fa);
        assert_eq!(state[2], 0x9e415c204d7b15e7);
        assert_eq!(state[3], 0xce0d71450fe44581);
        assert_eq!(state[4], 0xdd7c5fef57befe48);
    }

    #[test]
    fn state_permute_8() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_8();
        assert_eq!(state[0], 0x67ed228272f46eee);
        assert_eq!(state[1], 0x80bc0b097aad7944);
        assert_eq!(state[2], 0x2fa599382c6db215);
        assert_eq!(state[3], 0x368133fae2f7667a);
        assert_eq!(state[4], 0x28cefb195a7c651c);
    }

    #[test]
    fn state_permute_n() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let mut state2 = state.clone();

        state.permute_6();
        state2.permute_n(6);
        assert_eq!(state.x, state2.x);

        state.permute_8();
        state2.permute_n(8);
        assert_eq!(state.x, state2.x);

        state.permute_12();
        state2.permute_n(12);
        assert_eq!(state.x, state2.x);
    }

    #[test]
    fn state_convert_bytes() {
        let state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let bytes = state.as_bytes();

        // test TryFrom<&[u8]>
        let state2 = State::try_from(&bytes[..]);
        assert_eq!(state2.expect("try_from bytes").x, state.x);

        let state2 = State::from(&bytes);
        assert_eq!(state2.x, state.x);
    }
}
