# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.10](https://github.com/conradludgate/paseto-rs/compare/paseto-core-v0.1.0-rc.9...paseto-core-v0.1.0-rc.10) - 2026-07-25

### Other

- improve pke copy hygiene
- remove Zeroize on SealedKey to avoid unnecessary clone of encrypted data
- implement Zeroize and ZeroizeOnDrop traits from zeroize crate
- independent PKE key generation via PkeUnsealingVersion
- type nonce and tag sizes on the version trait

## [0.1.0-rc.9](https://github.com/conradludgate/paseto-rs/compare/paseto-core-v0.1.0-rc.8...paseto-core-v0.1.0-rc.9) - 2026-05-17

### Fixed

- fix typo: decryptiom -> decryption
