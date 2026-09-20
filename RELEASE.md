### Added

- Document the unaudited, pre-1.0 security posture and supported Noise r34
  surface, with safe-use guidance for key and PSK handling, peer authentication,
  protocol negotiation, framing, nonces and replay protection, rekeying, and
  failure handling.
- Add a security policy with private vulnerability reporting and a
  latest-release support policy.

### Changed

- **Breaking:** Replace bare session references with owner-aware opaque handles.
  Sessions remain local to the process that creates them, cannot be transferred
  or used concurrently from another process, and live until closed, their owner
  exits, or the `:decibel` application stops. Cross-process, closed, unknown,
  and phase-invalid use now raises `Decibel.SessionError` with stable reasons
  instead of leaking internal match, case, or map errors.
- **Breaking:** Reject attempts to move an outbound transport nonce backwards,
  preventing accidental key/nonce reuse. Callers should read the next outbound
  nonce with `get_nonce/2`; forward skips and inbound nonce selection remain
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
