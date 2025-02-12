# Changelog

## 0.2.4 - Jan 22, 2025

- Update deps
- Fix compiler errors

## 0.2.3 - June 6, 2023

- Fix unused alias warning.

## 0.2.2 - June 6, 2023

- Add `get_remote_key/1` to the public API.

## 0.2.1 - June 6, 2023 (Reverted)

- Add `get_public_key/2` to the public API.

## 0.2.0 - May 19, 2023
- Breaking change - renamed `set_n/3` and `get_n/2` to `set_nonce/3`
  and `get_nonce/2` respectively
- AEAD failure now raises a `Decibel.DecryptionError` rather than
  a `RuntimeError`. If this is raised during a handshake, this struct 
  will also contain any remote public keys processed during the
  handshake, up to the point of failure
- Added fallback tests
- Improved documentation around Noise Pipes and connectionless
  transports

## 0.1.1 - April 25, 2023

- Initial revision
