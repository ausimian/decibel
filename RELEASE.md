### Added

- Add `Decibel.split/2`, which moves both directions of an established
  interactive transport to other local processes in one operation and closes
  the original session. The process that completed the handshake no longer
  has to keep one direction.
