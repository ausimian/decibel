### Changed

- **Breaking:** Enforce Noise's 65,535-byte limit for handshake and transport
  messages. Transport plaintexts are now limited to 65,519 bytes to leave room
  for the authentication tag; applications must split and frame larger logical
  messages before passing them to Decibel.
