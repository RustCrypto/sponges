#![feature(test)]

extern crate test;

use ascon::aead;
use test::Bencher;

#[bench]
fn ascon_encrypt_bench(b: &mut Bencher) {
    let key = [4; 16];
    let iv = [8; 16];
    let aad = [3; 16];
    let message = [99; 1025];

    b.bytes = message.len() as u64;
    b.iter(|| aead::encrypt(&key, &iv, &message, &aad));
}

#[bench]
fn ascon_decrypt_bench(b: &mut Bencher) {
    let key = [4; 16];
    let iv = [8; 16];
    let aad = [3; 16];
    let message = [99; 1025];
    let (ciphertext, tag) = aead::encrypt(&key, &iv, &message, &aad);

    b.bytes = message.len() as u64;
    b.iter(|| aead::decrypt(&key, &iv, &ciphertext, &aad, &tag));
}
