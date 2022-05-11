# RustCrypto: Sponge Functions

[![Project Chat][chat-image]][chat-link] ![Apache2/MIT licensed][license-image] [![Dependency Status][deps-image]][deps-link]

Collection of [sponge functions] written in pure Rust.

## Supported Algorithms

| Crate      | Algorithm  | Crates.io | Documentation |
|------------|------------|-----------|---------------|
| [`keccak`] | [Keccak]   | [![crates.io](https://img.shields.io/crates/v/keccak.svg)](https://crates.io/crates/keccak) | [![Documentation](https://docs.rs/keccak/badge.svg)](https://docs.rs/keccak) |

## License

All crates licensed under either of

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[deps-image]: https://deps.rs/repo/github/RustCrypto/sponges/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/sponges
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

[//]: # (crates)

[`keccak`]: ./keccak

[//]: # (algorithms)

[sponge functions]: https://en.wikipedia.org/wiki/Sponge_function
[Keccak]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
