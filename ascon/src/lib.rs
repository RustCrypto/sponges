//! Pure Rust implementation of [Ascon], a family of authenticated encryption and
//! hashing algorithms designed to be lightweight and easy to implement.
//!
//! ## About
//!
//! Ascon is a family of lightweight algorithms built on a core permutation
//! algorithm. These algorithms include:
//!
//! - Authenticated Encryption with Associated Data (AEAD)
//! - Hash functions (HASH) and extendible-output functions (XOF)
//! - Pseudo-random functions (PRF) and message authentication codes (MAC)
//!
//! Ascon has been selected as [new standard for lightweight cryptography] in the
//! [NIST Lightweight Cryptography] competition, and has also been selected as the
//! primary choice for lightweight authenticated encryption in the final
//! portfolio of the [CAESAR competition].
//!
//! [Ascon]: https://ascon.iaik.tugraz.at/
//! [New standard for lightweight cryptography]: https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices
//! [NIST Lightweight Cryptography]: https://csrc.nist.gov/projects/lightweight-cryptography/finalists
//! [CAESAR competition]: https://competitions.cr.yp.to/caesar-submissions.html

#![no_std]
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

#[cfg(feature = "alloc")]
pub mod aead;

use core::convert::TryInto;

/// Key length.
const KEY_LEN: usize = 16;

/// State size.
const S_SIZE: usize = 320 / 8;

/// Rate: Sᵣ.
const RATE: usize = 128 / 8;

/// Ascon(a,b) a-parameter.
const A: usize = 12;

/// Ascon(a,b) b-parameter.
const B: usize = 8;

/// Ascon permutation.
pub fn permutation(s: &mut [u8], start: usize, rounds: usize) {
    let mut x = [0; 5];
    let mut t = [0; 5];

    #[allow(clippy::unwrap_used)]
    for (i, b) in x.iter_mut().enumerate() {
        *b = u64::from_be_bytes(s[(i * 8)..((i + 1) * 8)].try_into().unwrap());
    }

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

/// Initialize Ascon permutation.
pub fn initialization(s: &mut [u8], key: &[u8], nonce: &[u8]) {
    s[0] = KEY_LEN as u8 * 8;
    s[1] = RATE as u8 * 8;
    s[2] = A as u8;
    s[3] = B as u8;

    let mut pos = S_SIZE - 2 * KEY_LEN;
    s[pos..pos + key.len()].copy_from_slice(key);
    pos += KEY_LEN;
    s[pos..pos + nonce.len()].copy_from_slice(nonce);

    permutation(s, 12 - A, A);

    for (i, &b) in key.iter().enumerate() {
        s[pos + i] ^= b;
    }
}

/// Finalize Ascon permutation.
pub fn finalization(s: &mut [u8], key: &[u8]) {
    for (i, &b) in key.iter().enumerate() {
        s[RATE + i] ^= b;
    }
    permutation(s, 12 - A, A);
    for (i, &b) in key.iter().enumerate() {
        s[S_SIZE - KEY_LEN + i] ^= b;
    }
}
