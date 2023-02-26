#![feature(test)]

extern crate test;

use ascon::aead::{AeadInPlace, AsconAead, KeyInit};
use hex_literal::hex;
use test::Bencher;

const KEY: [u8; 16] = [4; 16];
const NONCE: [u8; 16] = [8; 16];
const AAD: [u8; 16] = [3; 16];
const PLAINTEXT: [u8; 1025] = [99; 1025];
const CIPHERTEXT: [u8; 1025] = hex!("d5cfb4650e0a82b9e86455de588cfd48c4bf240301efbf1981a57f00c5ec31eb9127d5da85fab0bf3c927b9d875cd1f71e0945f0281a0774e890bae1f98d488580c63e19972d73b6df19773503b0d8f0317727b8ab7681e15237eec369e8ea2915695d6f03f44541ea28f737574d5c7277361636a0a246fbc8c4b6764ef642b9a15211e11f5059fd08d173e4a9fff4cc55389d04a392f0a12dbccce67439e967bb8f39887b078cd68eaa8fd5a3c3b7299536c50a35b7871ab612417fdd1313527cbc82591d20417f2ef3dc37dc1298b32677daac9e79cf28307ceb886aea42694322ac5e978405fff9df6b9da86c83661fa165c957b830dc85350bb41ae6a6f9ee7c713d47b6277b54c64d0ceefd41945f23cfe4f0ba0ea39ba7c829c308ab53591817adeda57c4d3858fff07f57ec4100905e8568e855f61d558f7cffc3dc47b4e2ab9b90053caef52bede5871c5839b33f48e8822dbca59e96532ded31e809d901de72d65d5112ac067f7135670445bdec7e9f41287190dd091f906d6d98b6d15aa3fa475a2b4f99bc0e12e9c057140308a73572dcabad2e2140103028c075e9da74d92177aaea9d1899dace0ee8f4a9edfa9c4abc39a4b6239a2ea3841af1f90af884d10ef43b48924cba8474cb0162c8204acab4647cb680e9b64fb77e4d2195f63dd45e6c21b637db5c15101a72259e5af940ce9e5c0fe0b4affefef059e2982c32dfe50c0aefee368f15867ab2ff205fa855a895a0379b5678f432e25fd884771873acf6ee72fe4cf02c13843239b3114ff9e9bfebc44618bffc731b272cf08e627e47d759f1ae63191892d493a19fb54b96dd2132e416612d4e4a3bb536d0470c151c998a9ce5a44883ac395efa23e201734ef6a9e7ac1dade6a48fff8445e39a38157b5263cf9e52abf8cb604be9f1ed7ebe85e10933ab1f3e0546c17bbf7561233d7f95b32f8086fdbb06948af5a0ffd06dd47e89c3f4a419cc5b34300a76a542aeeae716563204f68f880cac077855297150fd217d6185116d542b64ce1319712760bf61fa1b6b52c8e9feb609bf6caa07b41ed80c7423cbe5390ec9851a2629d9d307971515c0a1696b0d4d52deabab089b945326b1e62a6ec5eb2cf2c58a5af0404962923a0c8605b6d55fd899765b193db8f5a849ecab478e187476779cf5f08d38a812b14ddff6143870ce5d9afc3e2eda91624067654940856421f5a8e0f6e3eefe888bd11c9364a29e2821374a1550e888359230ba863424746c793708e0ba23be967fa527ee5989eaf48541928e594ea846d67d5a6a56aa886be7b693d662cd675c786687c0d870bf19ab7564fb0b87bc6bba157ae04f482fca52858f8ff600141efa24f2f29cb0b8e222d88d9bfd9e60818474e55cc2b11e70125a956934c75cad4207f83b372c501ca7864bf8d387d0f81ec1cc872ff180");
const TAG: [u8; 16] = hex!("17d7dca595adcaaddf537a1e9fd02854");

#[bench]
fn ascon_decrypt_bench(b: &mut Bencher) {
    let aead = AsconAead::<12, 8>::new(&KEY.into());
    b.bytes = CIPHERTEXT.len() as u64;
    b.iter(|| {
        let mut buffer = CIPHERTEXT;
        aead.decrypt_in_place_detached(&NONCE.into(), &AAD, &mut buffer, &TAG.into())
            .unwrap();
    });
}

#[bench]
fn ascon_encrypt_bench(b: &mut Bencher) {
    let aead = AsconAead::<12, 8>::new(&KEY.into());
    b.bytes = PLAINTEXT.len() as u64;
    b.iter(|| {
        let mut buffer = PLAINTEXT;
        aead.encrypt_in_place_detached(&NONCE.into(), &AAD, &mut buffer)
            .unwrap();
    });
}
