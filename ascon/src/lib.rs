extern crate byteorder;

mod ops;
mod util;

use ops::{finalization, initialization, permutation, process_aad};

const KEY_LEN: usize = 16;
const S_SIZE: usize = 320 / 8;
const RATE: usize = 128 / 8;
const A: usize = 12;
const B: usize = 8;

#[derive(Debug)]
pub enum DecryptFail {
    TagLengthError,
    AuthenticationFail,
}

pub fn aead_encrypt(key: &[u8], iv: &[u8], message: &[u8], aad: &[u8]) -> (Vec<u8>, [u8; KEY_LEN]) {
    let s = aad.len() / RATE + 1;
    let t = message.len() / RATE + 1;
    let l = message.len() % RATE;

    let mut ss = [0; S_SIZE];
    let mut aa = vec![0; s * RATE];
    let mut mm = vec![0; t * RATE];

    let mut output = vec![0; message.len()];
    let mut tag = [0; KEY_LEN];

    // pad aad
    aa[..aad.len()].copy_from_slice(aad);
    aa[aad.len()] = 0x80;
    // pad message
    mm[..message.len()].copy_from_slice(message);
    mm[message.len()] = 0x80;

    // init
    initialization(&mut ss, key, iv);

    // aad
    if !aad.is_empty() {
        process_aad(&mut ss, &aa, s);
    }
    ss[S_SIZE - 1] ^= 1;

    // plaintext
    for i in 0..(t - 1) {
        for j in 0..RATE {
            ss[j] ^= mm[i * RATE + j];
        }
        output[(i * RATE)..(i * RATE + RATE)].copy_from_slice(&ss[..RATE]);
        permutation(&mut ss, 12 - B, B);
    }
    for j in 0..RATE {
        ss[j] ^= mm[(t - 1) * RATE + j];
    }
    for j in 0..l {
        output[(t - 1) * RATE + j] = ss[j];
    }

    // finalization
    finalization(&mut ss, key);

    // tag
    tag.copy_from_slice(&ss[S_SIZE - KEY_LEN..]);

    (output, tag)
}

pub fn aead_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, DecryptFail> {
    if tag.len() != KEY_LEN {
        Err(DecryptFail::TagLengthError)?
    };

    let s = aad.len() / RATE + 1;
    let t = ciphertext.len() / RATE + 1;
    let l = ciphertext.len() % RATE;

    let mut ss = [0; S_SIZE];
    let mut aa = vec![0; s * RATE];
    let mut mm = vec![0; t * RATE];

    // pad aad
    aa[..aad.len()].copy_from_slice(aad);
    aa[aad.len()] = 0x80;

    // init
    initialization(&mut ss, key, iv);

    // aad
    if !aad.is_empty() {
        process_aad(&mut ss, &aa, s);
    }
    ss[S_SIZE - 1] ^= 1;

    // ciphertext
    for i in 0..(t - 1) {
        for j in 0..RATE {
            mm[i * RATE + j] = ss[j] ^ ciphertext[i * RATE + j];
        }
        ss[..RATE].copy_from_slice(&ciphertext[(i * RATE)..(i * RATE + RATE)]);
        permutation(&mut ss, 12 - B, B);
    }
    for j in 0..l {
        mm[(t - 1) * RATE + j] = ss[j] ^ ciphertext[(t - 1) * RATE + j];
    }
    for j in 0..l {
        ss[j] = ciphertext[(t - 1) * RATE + j];
    }
    ss[l] ^= 0x80;

    // finalization
    finalization(&mut ss, key);

    if util::eq(&ss[S_SIZE - KEY_LEN..], tag) {
        Ok(mm[..ciphertext.len()].into())
    } else {
        Err(DecryptFail::AuthenticationFail)
    }
}

#[test]
fn ascon_test() {
    let key = [0; 16];
    let iv = [0; 16];
    let aad = [0; 16];
    let message = [0; 64];

    let (ciphertext, tag) = aead_encrypt(&key, &iv, &message, &aad);
    let plaintext = aead_decrypt(&key, &iv, &ciphertext, &aad, &tag).unwrap();
    assert_eq!(plaintext, &message[..]);
    assert!(util::eq(&message, &plaintext));
}

#[test]
fn ascon_tv_test() {
    let key = [0; 16];
    let iv = [0; 16];
    let aad = b"ASCON";
    let message = b"ascon";

    let (ciphertext, tag) = aead_encrypt(&key, &iv, message, aad);
    assert_eq!(ciphertext, [0x4c, 0x8c, 0x42, 0x89, 0x49]);
    assert_eq!(
        tag,
        [
            0x65, 0xfd, 0x17, 0xb6, 0xd3, 0x0c, 0xd8, 0x76, 0xa0, 0x5a, 0x8e, 0xfc, 0xec, 0xad,
            0x99, 0x3a
        ]
    );

    let plaintext = aead_decrypt(&key, &iv, &ciphertext, aad, &tag).unwrap();
    assert_eq!(plaintext, message);
}
