### Added

- Add `Decibel.split/3`, which moves one direction of an established
  interactive transport to a designated local process so that sending and
  receiving can run in separate processes. The target accepts it with
  `Decibel.accept_handoff/1`.
- Add a `:cause` field to `Decibel.TransportDirectionError`: `:one_way` for a
  direction a one-way handshake does not permit, or `:split` for a direction
  moved by `Decibel.split/3`.
