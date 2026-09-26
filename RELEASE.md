### Changed

- Read a session's stored state once per operation instead of twice.
  Operations that update session state, such as `encrypt/3`, `decrypt/3`,
  `set_nonce/3` and `rekey/2`, no longer re-read the entry before writing it
  back, which slightly reduces their per-call overhead.
