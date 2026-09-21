### Added

- Add runnable NN and IK getting-started examples with application framing,
  remote-key trust validation, and focused recipes for keys, PSKs, handshake
  payloads, channel binding, rekeying, fallback, connectionless delivery,
  session cleanup, and error handling.
- Add fixed-seed adversarial state-machine coverage for malformed and truncated
  input, invalid call order, fragmented iodata, authentication-failure retries,
  and nonce boundaries across the supported Noise pattern and primitive families.
- Pin each checked-in interoperability vector to its upstream revision, licence,
  checksums, and local transformation, with offline verification and explicit
  regeneration commands.
- Document the unaudited, pre-1.0 security posture and supported Noise r34
  surface, with safe-use guidance for key and PSK handling, peer authentication,
  protocol negotiation, framing, nonces and replay protection, rekeying, and
  failure handling.
- Add a security policy with private vulnerability reporting and a
  latest-release support policy.

### Changed

- Correct handshake-hash, Diffie-Hellman keypair, and nonce types so HexDocs
  accurately describes 32- and 64-byte hashes and the keys stored during
  handshakes.
- Gate releases on warning-free Dialyzer and documentation builds, an exact
  Hex package manifest, at least 97% line coverage, and dependency retirement
  and security-advisory audits.
- **Breaking:** Finalize the 1.0 session API with idiomatic
  `handshake_complete?/1`, `handshake_hash/1`, `nonce/2`, and `remote_key/1`
  accessors. The 0.2 names remain deprecated for the 1.0 compatibility release
  and are scheduled for removal in 2.0.
- Make the raising API contract explicit: data-producing operations return
  their payloads directly, state-only operations return `:ok`, and rejected
  operations raise stable exceptions without committing session state.
- **Breaking:** Remove the unsupported custom `:registry` construction option.
  The `:swap` option remains available for interactive fallback handshakes and
  is now fully documented.
- **Breaking:** Replace bare session references with owner-aware opaque handles.
  Sessions remain local to the process that creates them, cannot be transferred
  or used concurrently from another process, and live until closed or until
  their owner exits. Cross-process, closed, unknown, and phase-invalid use now
  raises `Decibel.SessionError` with stable reasons instead of leaking internal
  match, case, or map errors.
- **Breaking:** Reject attempts to move an outbound transport nonce backwards,
  preventing accidental key/nonce reuse. Callers should read the next outbound
  nonce with `nonce/2`; forward skips and inbound nonce selection remain
  available through `set_nonce/3`.
- Make connectionless replay protection explicitly application-owned, with a
  bounded replay-window example that records nonces only after successful
  authentication and guidance for coordinated rekeying.
- **Breaking:** Generate a fresh local ephemeral keypair for every ordinary
  handshake and reject caller-supplied `:e` keypairs outside fallback
  pre-messages, preventing accidental transport-key and nonce reuse across
  sessions.
- **Breaking:** Enforce Noise's 65,535-byte limit for handshake and transport
  messages. Transport plaintexts are now limited to 65,519 bytes to leave room
  for the authentication tag; applications must split and frame larger logical
  messages before passing them to Decibel.

### Fixed

- Validate all role-specific static key material, prologue data, and
  construction options during session creation, raising stable field-level
  errors before storing session state.
- Reject malformed or non-canonical Noise protocol names, invalid modifier
  placements, and missing, malformed, or unused pre-shared keys during session
  creation instead of silently omitting PSK authentication.
- Return `Decibel.DecryptionError` with a stable reason for truncated,
  unauthenticated, or invalid-key peer messages, preserving processed remote
  keys and leaving session state unchanged.
- Allow Noise's final usable transport nonce (`2^64 - 2`) once, then raise
  `Decibel.NonceError` on exhaustion; `set_nonce/3` now rejects reserved and
  out-of-range nonce values without changing session state.
- Prevent responders from encrypting and initiators from decrypting transport
  messages after `N`, `K`, and `X` one-way handshakes. Operations targeting the
  discarded transport direction now raise `Decibel.TransportDirectionError`.
