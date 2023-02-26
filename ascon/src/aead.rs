//! Authenticated Encryption with Associated Data.

use crate::{Ascon, Key, Nonce, KEY_SIZE, RATE, S_SIZE};
use alloc::{vec, vec::Vec};

/// Ascon(a,b) `b`-parameter.
const B: usize = 8;

/// Tag length.
const TAG_LEN: usize = 16;

/// Authentication tag.
type Tag = [u8; TAG_LEN];

/// Decryption errors.
#[derive(Debug)]
pub enum DecryptFail {
    /// Invalid tag length.
    TagLengthError,

    /// Authentication failure (invalid tag).
    AuthenticationFail,
}

/// AEAD encryption.
pub fn encrypt(key: &Key, nonce: &Nonce, message: &[u8], aad: &[u8]) -> (Vec<u8>, Tag) {
    let s = aad.len() / RATE + 1;
    let t = message.len() / RATE + 1;
    let l = message.len() % RATE;

    let mut aa = vec![0; s * RATE];
    let mut mm = vec![0; t * RATE];

    let mut output = vec![0; message.len()];

    // pad aad
    aa[..aad.len()].copy_from_slice(aad);
    aa[aad.len()] = 0x80;

    // pad message
    mm[..message.len()].copy_from_slice(message);
    mm[message.len()] = 0x80;

    // init
    let mut ss = Ascon::new(key, nonce);

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
        output[(i * RATE)..(i * RATE + RATE)].copy_from_slice(&ss.state[..RATE]);
        ss.permutation(12 - B, B);
    }

    for j in 0..RATE {
        ss.state[j] ^= mm[(t - 1) * RATE + j];
    }

    for j in 0..l {
        output[(t - 1) * RATE + j] = ss.state[j];
    }

    // tag
    let mut tag = Tag::default();
    tag.copy_from_slice(&ss.finalize()[S_SIZE - KEY_SIZE..]);

    (output, tag)
}

/// AEAD decryption.
pub fn decrypt(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, DecryptFail> {
    if tag.len() != KEY_SIZE {
        Err(DecryptFail::TagLengthError)?
    };

    let s = aad.len() / RATE + 1;
    let t = ciphertext.len() / RATE + 1;
    let l = ciphertext.len() % RATE;

    let mut aa = vec![0; s * RATE];
    let mut mm = vec![0; t * RATE];

    // pad aad
    aa[..aad.len()].copy_from_slice(aad);
    aa[aad.len()] = 0x80;

    // init
    let mut ss = Ascon::new(key, nonce);

    // aad
    if !aad.is_empty() {
        process_aad(&mut ss, &aa, s);
    }

    ss.state[S_SIZE - 1] ^= 1;

    // ciphertext
    for i in 0..(t - 1) {
        for j in 0..RATE {
            mm[i * RATE + j] = ss.state[j] ^ ciphertext[i * RATE + j];
        }
        ss.state[..RATE].copy_from_slice(&ciphertext[(i * RATE)..(i * RATE + RATE)]);
        ss.permutation(12 - B, B);
    }

    for j in 0..l {
        mm[(t - 1) * RATE + j] = ss.state[j] ^ ciphertext[(t - 1) * RATE + j];
    }

    for j in 0..l {
        ss.state[j] = ciphertext[(t - 1) * RATE + j];
    }

    ss.state[l] ^= 0x80;

    // finalization
    let expected_tag = ss.finalize();

    if ct_eq(&expected_tag[S_SIZE - KEY_SIZE..], tag) {
        Ok(mm[..ciphertext.len()].into())
    } else {
        Err(DecryptFail::AuthenticationFail)
    }
}

// TODO(tarcieri): use `subtle`
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        false
    } else {
        a.iter()
            .zip(b)
            .map(|(x, y)| x ^ y)
            .fold(0, |sum, next| sum | next)
            .eq(&0)
    }
}

fn process_aad(ss: &mut Ascon, aa: &[u8], s: usize) {
    for i in 0..s {
        for j in 0..RATE {
            ss.state[j] ^= aa[i * RATE + j];
        }

        ss.permutation(12 - B, B);
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    #[test]
    fn round_trip() {
        let key = [0; 16];
        let iv = [0; 16];
        let aad = [0; 16];
        let message = [0; 64];

        let (ciphertext, tag) = encrypt(&key, &iv, &message, &aad);
        let plaintext = decrypt(&key, &iv, &ciphertext, &aad, &tag).unwrap();
        assert_eq!(plaintext, &message[..]);
    }

    #[test]
    fn test_vectors() {
        let key = [0; 16];
        let iv = [0; 16];
        let aad = b"ASCON";
        let message = b"ascon";

        let (ciphertext, tag) = encrypt(&key, &iv, message, aad);
        assert_eq!(ciphertext, [0x4c, 0x8c, 0x42, 0x89, 0x49]);
        assert_eq!(
            tag,
            [
                0x65, 0xfd, 0x17, 0xb6, 0xd3, 0x0c, 0xd8, 0x76, 0xa0, 0x5a, 0x8e, 0xfc, 0xec, 0xad,
                0x99, 0x3a
            ]
        );

        let plaintext = decrypt(&key, &iv, &ciphertext, aad, &tag).unwrap();
        assert_eq!(plaintext, message);
    }
}
