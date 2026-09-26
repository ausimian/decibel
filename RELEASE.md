### Added

- Add `Decibel.encrypt_with_nonce/3`, which encrypts under the next outbound
  nonce and returns that nonce with the ciphertext, and a `:nonce` option for
  `Decibel.decrypt/4`, which decrypts at a given inbound nonce. Protocols that
  carry an explicit nonce with each message can now seal or open it in one
  session operation instead of two (`nonce/2` then `encrypt/3`, or
  `set_nonce/3` then `decrypt/3`). Unlike `set_nonce/3` followed by
  `decrypt/3`, a failed decryption at a given nonce leaves the inbound nonce
  unchanged.
