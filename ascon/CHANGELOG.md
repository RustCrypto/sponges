# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.3.1 (2023-03-19)
### Changed
- Drop MSRV to 1.56 ([#51])

[#51]: https://github.com/RustCrypto/sponges/pull/51

## 0.3.0 (2023-03-17)
### Added
- `State` type and permutation from `ascon-core` crate ([#49])
- `no_unroll` feature

### Removed
- AEAD API and `aead` dependency
  The implementation of the AEAD API is provided by `ascon-aead`.
- `Ascon`, `Key`, `Nonce` types
- `alloc`, `std`, and `aead` features

[#49]: https://github.com/RustCrypto/sponges/pull/49

## 0.2.0 (2023-02-25)
### Added
-  `no_std` support ([#36])
- `Ascon` permutation type ([#39])
- `Key` type alias ([#42])
- `Nonce` type alias ([#43])

### Changed
- 2021 edition ([#40])
- Use `aead` crate for AEAD API ([#44])
- MSRV 1.60 ([#44])

### Removed
- `byteorder` dependency ([#37])

[#36]: https://github.com/RustCrypto/sponges/pull/36
[#37]: https://github.com/RustCrypto/sponges/pull/37
[#39]: https://github.com/RustCrypto/sponges/pull/39
[#40]: https://github.com/RustCrypto/sponges/pull/40
[#42]: https://github.com/RustCrypto/sponges/pull/42
[#43]: https://github.com/RustCrypto/sponges/pull/43
[#44]: https://github.com/RustCrypto/sponges/pull/44

## 0.1.4 (2017-03-27)

## 0.1.3 (2016-11-13)

## 0.1.2 (2016-11-01)

## 0.1.1 (2016-11-01)

## 0.1.0 (2016-07-26)
