# [RustCrypto]: Ascon permutation

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the permutation of [Ascon], a family of
authenticated encryption and hashing algorithms designed to be lightweight and
easy to implement.

[Documentation][docs-link]

## About

Ascon is a family of lightweight algorithms built on a core permutation
algorithm. These algorithms include:

- [x] [`ascon-aead`]: Authenticated Encryption with Associated Data
- [x] [`ascon-hash`]: Hash functions and extendible-output functions (XOF)
- [ ] Pseudo-random functions (PRF) and message authentication codes (MAC)

Ascon has been selected as [new standard for lightweight cryptography] in the
[NIST Lightweight Cryptography] competition, and has also been selected as the
primary choice for lightweight authenticated encryption in the final
portfolio of the [CAESAR competition].

## Minimum Supported Rust Version

This crate requires **Rust 1.81** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/ascon
[crate-link]: https://crates.io/crates/ascon
[docs-image]: https://docs.rs/ascon/badge.svg
[docs-link]: https://docs.rs/ascon/
[build-image]: https://github.com/RustCrypto/sponges/actions/workflows/ascon.yml/badge.svg
[build-link]: https://github.com/RustCrypto/sponges/actions/workflows/ascon.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/369879-sponges

[//]: # (links)

[`ascon-aead`]: https://github.com/RustCrypto/AEADs/tree/master/ascon-aead
[`ascon-hash`]: https://github.com/RustCrypto/hashes/tree/master/ascon-hash
[RustCrypto]: https://github.com/rustcrypto
[Ascon]: https://ascon.iaik.tugraz.at/
[New standard for lightweight cryptography]: https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices
[NIST Lightweight Cryptography]: https://csrc.nist.gov/projects/lightweight-cryptography/finalists
[CAESAR competition]: https://competitions.cr.yp.to/caesar-submissions.html
