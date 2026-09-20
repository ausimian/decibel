### Changed

- **Breaking:** Enforce Noise's 65,535-byte limit for handshake and transport
  messages. Transport plaintexts are now limited to 65,519 bytes to leave room
  for the authentication tag; applications must split and frame larger logical
  messages before passing them to Decibel.

### Fixed

- Return `Decibel.DecryptionError` with a stable reason for truncated,
  unauthenticated, or invalid-key peer messages, preserving processed remote
  keys and leaving session state unchanged.
- Allow Noise's final usable transport nonce (`2^64 - 2`) once, then raise
  `Decibel.NonceError` on exhaustion; `set_nonce/3` now rejects reserved and
  out-of-range nonce values without changing session state.
- Prevent responders from encrypting and initiators from decrypting transport
  messages after `N`, `K`, and `X` one-way handshakes. Operations targeting the
  discarded transport direction now raise `Decibel.TransportDirectionError`.
