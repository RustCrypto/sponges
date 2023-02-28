#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "aead")]
pub mod aead;

#[cfg(feature = "aead")]
pub use crate::aead::AsconAead;

use core::convert::TryInto;

/// Size of an Ascon key in bytes.
const KEY_SIZE: usize = 16;

/// Size of an Ascon nonce in bytes.
const NONCE_SIZE: usize = 16;

/// State size in bits.
const S_BITS: usize = 320;

/// State size.
const S_SIZE: usize = S_BITS / 8;

/// Rate: Sᵣ.
const RATE: usize = 128 / 8;

/// Ascon permutation key.
pub type Key = [u8; KEY_SIZE];

/// Ascon nonce.
pub type Nonce = [u8; NONCE_SIZE];

/// Ascon permutation state.
type State = [u8; S_SIZE];

/// Ascon(a,b) permutation.
pub struct Ascon<const A: usize = 12, const B: usize = 8> {
    key: Key,
    state: State,
}

impl<const A: usize, const B: usize> Ascon<A, B> {
    /// Initialize Ascon permutation.
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let mut state = [0; S_SIZE];
        state[0] = KEY_SIZE as u8 * 8;
        state[1] = RATE as u8 * 8;
        state[2] = A as u8;
        state[3] = B as u8;

        let pos = S_SIZE - KEY_SIZE - NONCE_SIZE;
        let (k, n) = state[pos..].split_at_mut(KEY_SIZE);
        k.copy_from_slice(key);
        n.copy_from_slice(nonce);

        permutation(&mut state, 12 - A, A);

        for (i, &b) in key.iter().enumerate() {
            state[pos + KEY_SIZE + i] ^= b;
        }

        Self { key: *key, state }
    }

    /// Perform Ascon permutation on internal state.
    pub fn permutation(&mut self, start: usize, rounds: usize) {
        permutation(&mut self.state, start, rounds);
    }

    /// Finalize Ascon permutation.
    #[inline(always)]
    #[must_use]
    pub fn finalize(self) -> [u8; S_SIZE] {
        let mut s = self.state;

        for (i, &b) in self.key.iter().enumerate() {
            s[RATE + i] ^= b;
        }

        permutation(&mut s, 12 - A, A);

        for (i, &b) in self.key.iter().enumerate() {
            s[S_SIZE - KEY_SIZE + i] ^= b;
        }

        s
    }
}

/// Ascon permutation.
// TODO(tarcieri): change `s` to `&mut [u8; 40]`
fn permutation(s: &mut [u8], start: usize, rounds: usize) {
    let mut x = [0; 5];
    let mut t = [0; 5];

    assert_eq!(s.len(), 8 * x.len());

    // TODO(tarcieri): use `array_chunks` to eliminate `unwrap`
    #[allow(clippy::unwrap_used)]
    s.chunks_exact(8)
        .map(|c| c.try_into().unwrap())
        .map(u64::from_be_bytes)
        .zip(x.iter_mut())
        .for_each(|(inp, out)| *out = inp);

    for i in start as u64..(start + rounds) as u64 {
        x[2] ^= ((0xfu64 - i) << 4) | i;

        x[0] ^= x[4];
        x[4] ^= x[3];
        x[2] ^= x[1];
        t[0] = x[0];
        t[1] = x[1];
        t[2] = x[2];
        t[3] = x[3];
        t[4] = x[4];
        t[0] = !t[0];
        t[1] = !t[1];
        t[2] = !t[2];
        t[3] = !t[3];
        t[4] = !t[4];
        t[0] &= x[1];
        t[1] &= x[2];
        t[2] &= x[3];
        t[3] &= x[4];
        t[4] &= x[0];
        x[0] ^= t[1];
        x[1] ^= t[2];
        x[2] ^= t[3];
        x[3] ^= t[4];
        x[4] ^= t[0];
        x[1] ^= x[0];
        x[0] ^= x[4];
        x[3] ^= x[2];
        x[2] = !x[2];

        x[0] ^= x[0].rotate_right(19) ^ x[0].rotate_right(28);
        x[1] ^= x[1].rotate_right(61) ^ x[1].rotate_right(39);
        x[2] ^= x[2].rotate_right(1) ^ x[2].rotate_right(6);
        x[3] ^= x[3].rotate_right(10) ^ x[3].rotate_right(17);
        x[4] ^= x[4].rotate_right(7) ^ x[4].rotate_right(41);
    }

    for (i, &b) in x.iter().enumerate() {
        s[(i * 8)..((i + 1) * 8)].copy_from_slice(&b.to_be_bytes())
    }
}
