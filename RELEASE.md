### Changed

- **Breaking:** Enforce Noise's 65,535-byte limit for handshake and transport
  messages. Transport plaintexts are now limited to 65,519 bytes to leave room
  for the authentication tag; applications must split and frame larger logical
  messages before passing them to Decibel.

### Fixed

- Prevent responders from encrypting and initiators from decrypting transport
  messages after `N`, `K`, and `X` one-way handshakes. Operations targeting the
  discarded transport direction now raise `Decibel.TransportDirectionError`.
