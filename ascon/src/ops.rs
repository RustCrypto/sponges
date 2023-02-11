use crate::{
    util::{u64_to_u8, u8_to_u64},
    A, B, KEY_LEN, RATE, S_SIZE,
};

pub fn permutation(s: &mut [u8], start: usize, rounds: usize) {
    let mut x = [0; 5];
    let mut t = [0; 5];
    u8_to_u64(s, &mut x);

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

    u64_to_u8(&x, s);
}

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

pub fn finalization(s: &mut [u8], key: &[u8]) {
    for (i, &b) in key.iter().enumerate() {
        s[RATE + i] ^= b;
    }
    permutation(s, 12 - A, A);
    for (i, &b) in key.iter().enumerate() {
        s[S_SIZE - KEY_LEN + i] ^= b;
    }
}

pub fn process_aad(ss: &mut [u8], aa: &[u8], s: usize) {
    for i in 0..s {
        for j in 0..RATE {
            ss[j] ^= aa[i * RATE + j];
        }
        permutation(ss, 12 - B, B);
    }
}
