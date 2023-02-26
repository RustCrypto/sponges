//! Authenticated Encryption with Associated Data.

pub use ::aead::{self, AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser};

use crate::{Ascon, KEY_SIZE, RATE, S_SIZE};
use ::aead::consts::{U0, U16};

// TODO(tarcieri): remove hard dependency on alloc
use alloc::vec;

/// Ascon AEAD key.
pub type Key = ::aead::generic_array::GenericArray<u8, U16>;

/// Ascon AEAD nonce.
pub type Nonce = ::aead::generic_array::GenericArray<u8, U16>;

/// Ascon AEAD authentication tag.
pub type Tag = ::aead::generic_array::GenericArray<u8, U16>;

/// Ascon AEAD encryption.
#[derive(Clone)]
pub struct AsconAead<const A: usize = 12, const B: usize = 8> {
    key: Key,
}

impl<const A: usize, const B: usize> KeySizeUser for AsconAead<A, B> {
    type KeySize = U16;
}

impl<const A: usize, const B: usize> KeyInit for AsconAead<A, B> {
    fn new(key_bytes: &Key) -> Self {
        Self { key: *key_bytes }
    }
}

impl<const A: usize, const B: usize> AeadCore for AsconAead<A, B> {
    type NonceSize = U16;
    type TagSize = U16;
    type CiphertextOverhead = U0;
}

impl<const A: usize, const B: usize> AeadInPlace for AsconAead<A, B> {
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        let s = aad.len() / RATE + 1;
        let t = buffer.len() / RATE + 1;
        let l = buffer.len() % RATE;

        let mut aa = vec![0; s * RATE];
        let mut mm = vec![0; t * RATE];

        // pad aad
        aa[..aad.len()].copy_from_slice(aad);
        aa[aad.len()] = 0x80;

        // pad message
        mm[..buffer.len()].copy_from_slice(buffer);
        mm[buffer.len()] = 0x80;

        // init
        let mut ss = Ascon::<A, B>::new(self.key.as_ref(), nonce.as_ref());

        // aad
        if !aad.is_empty() {
            process_aad(&mut ss, &aa, s);
        }

        ss.state[S_SIZE - 1] ^= 1;

        // plaintext
        for i in 0..(t - 1) {
            for j in 0..RATE {
                ss.state[j] ^= mm[i * RATE + j];
            }
            buffer[(i * RATE)..(i * RATE + RATE)].copy_from_slice(&ss.state[..RATE]);
            ss.permutation(12 - B, B);
        }

        for j in 0..RATE {
            ss.state[j] ^= mm[(t - 1) * RATE + j];
        }

        for j in 0..l {
            buffer[(t - 1) * RATE + j] = ss.state[j];
        }

        // tag
        let mut tag = Tag::default();
        tag.copy_from_slice(&ss.finalize()[S_SIZE - KEY_SIZE..]);

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        let s = aad.len() / RATE + 1;
        let t = buffer.len() / RATE + 1;
        let l = buffer.len() % RATE;

        let mut aa = vec![0; s * RATE];
        let mut mm = vec![0; t * RATE];

        // pad aad
        aa[..aad.len()].copy_from_slice(aad);
        aa[aad.len()] = 0x80;

        // init
        let mut ss = Ascon::<A, B>::new(self.key.as_ref(), nonce.as_ref());

        // aad
        if !aad.is_empty() {
            process_aad(&mut ss, &aa, s);
        }

        ss.state[S_SIZE - 1] ^= 1;

        // ciphertext
        for i in 0..(t - 1) {
            for j in 0..RATE {
                mm[i * RATE + j] = ss.state[j] ^ buffer[i * RATE + j];
            }
            ss.state[..RATE].copy_from_slice(&buffer[(i * RATE)..(i * RATE + RATE)]);
            ss.permutation(12 - B, B);
        }

        for j in 0..l {
            mm[(t - 1) * RATE + j] = ss.state[j] ^ buffer[(t - 1) * RATE + j];
        }

        for j in 0..l {
            ss.state[j] = buffer[(t - 1) * RATE + j];
        }

        ss.state[l] ^= 0x80;

        // finalization
        let expected_tag = ss.finalize();

        use subtle::ConstantTimeEq;
        if expected_tag[S_SIZE - KEY_SIZE..]
            .ct_eq(tag.as_slice())
            .into()
        {
            buffer.copy_from_slice(&mm[..buffer.len()]);
            Ok(())
        } else {
            Err(Error)
        }
    }
}

fn process_aad<const A: usize, const B: usize>(ss: &mut Ascon<A, B>, aa: &[u8], s: usize) {
    for i in 0..s {
        for j in 0..RATE {
            ss.state[j] ^= aa[i * RATE + j];
        }

        ss.permutation(12 - B, B);
    }
}

#[cfg(test)]
mod tests {
    use super::{AeadInPlace, AsconAead, KeyInit};
    use hex_literal::hex;

    #[test]
    fn round_trip() {
        let key = [0; 16];
        let nonce = [0; 16];
        let aad = [0; 16];
        let message = [0; 64];

        let aead = AsconAead::<12, 8>::new(&key.into());
        let mut buffer = message;

        let tag = aead
            .encrypt_in_place_detached(&nonce.into(), &aad, &mut buffer)
            .unwrap();
        aead.decrypt_in_place_detached(&nonce.into(), &aad, &mut buffer, &tag)
            .unwrap();

        assert_eq!(message, buffer);
    }

    #[test]
    fn test_vectors() {
        const KEY: [u8; 16] = [0; 16];
        const NONCE: [u8; 16] = [0; 16];
        const AAD: &[u8; 5] = b"ASCON";
        const PLAINTEXT: &[u8; 5] = b"ascon";
        const CIPHERTEXT: &[u8; 5] = &hex!("4c8c428949");
        const TAG: &[u8; 16] = &hex!("65fd17b6d30cd876a05a8efcecad993a");

        let aead = AsconAead::<12, 8>::new(&KEY.into());
        let mut buffer = *PLAINTEXT;

        let tag = aead
            .encrypt_in_place_detached(&NONCE.into(), AAD, &mut buffer)
            .unwrap();

        assert_eq!(CIPHERTEXT, &buffer);
        assert_eq!(TAG, tag.as_slice());

        aead.decrypt_in_place_detached(&NONCE.into(), AAD, &mut buffer, &tag)
            .unwrap();

        assert_eq!(PLAINTEXT, &buffer);
    }
}
