### Fixed

- Remove a session's entry from its owner process when it is closed or handed
  off, including accepted handoffs. Each closed session previously left a
  marker in the owner's process dictionary until the owner exited, so a
  long-lived owner grew by roughly 105–150 bytes for every session it had
  created. Operations on closed handles still raise `Decibel.SessionError`
  with `reason: :closed`, and handles Decibel never issued still use
  `reason: :unknown`.
