# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.10](https://github.com/conradludgate/paseto-rs/compare/paseto-v1-v0.1.0-rc.9...paseto-v1-v0.1.0-rc.10) - 2026-07-25

### Other

- final encryption intermediate values
- zeroize intermediate ek and ak keys
- zeroize intermediate secret values during encryption
- improve pke copy hygiene
- implement Zeroize and ZeroizeOnDrop traits from zeroize crate
- independent PKE key generation via PkeUnsealingVersion
- update crypto crates
- type nonce and tag sizes on the version trait

## [0.1.0-rc.9](https://github.com/conradludgate/paseto-rs/compare/paseto-v1-v0.1.0-rc.8...paseto-v1-v0.1.0-rc.9) - 2026-05-17

### Other

- Merge pull request #1 from deadbaed/fix-typo-decryption
- update rustcrypto and rand
