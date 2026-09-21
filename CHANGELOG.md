# Changelog

<!-- %% CHANGELOG_ENTRIES %% -->

## 1.0.1 - 2026-09-21

### Fixed

- Link the README's documentation list to HexDocs and its security policy to
  the repository. The hex.pm package page rewrites repository-relative links
  into tarball previews, so those entries served raw markdown and the security
  policy link returned 404.

## 1.0.0 - 2026-09-21

Decibel 1.0 establishes its first stable public API, strengthens protocol-boundary
validation, and documents a safer integration contract. The project remains
unaudited and has not been declared production-ready; see the
[security posture](https://hexdocs.pm/decibel/security.html#security-posture).

### Added

- Add `Decibel.ReplayWindow`, a pure bitmap replay helper for
  application-owned connectionless state, with executable guidance for
  ordered, lossy in-order, and lossy reordered transports.
- Publish a Getting Started guide with runnable NN and IK examples, application
  framing, remote-key trust validation, and focused recipes for keys, PSKs,
  handshake payloads, channel binding, rekeying, fallback, connectionless
  delivery, session cleanup, and error handling, alongside dedicated security,
  Noise Pipes, connectionless transport, and 1.0 upgrade guides.
- Publish the supported Noise r34 patterns, modifiers, primitives, and runtime
  combinations, together with safe-use guidance for peer authentication, key
  and PSK handling, negotiation, framing, replay protection, rekeying, and
  failure handling.
- Add a security policy with private vulnerability reporting and a
  latest-release support policy.
- Add stable, machine-readable exception contracts for peer-message failures,
  nonce failures, discarded one-way directions, and session ownership,
  lifetime, and phase errors. Rejected operations leave session state
  unchanged.

### Changed

- **Breaking:** Require Elixir `~> 1.18` instead of `~> 1.14`. **Migration:**
  upgrade the application to Elixir 1.18 or later before updating Decibel.
- **Breaking:** Make `handshake_complete?/1`, `handshake_hash/1`, `nonce/2`,
  and `remote_key/1` the canonical accessors. **Migration:** rename calls from
  `is_handshake_complete?/1`, `get_handshake_hash/1`, `get_nonce/2`, and
  `get_remote_key/1`; the 0.2 names remain deprecated aliases until 2.0.
- **Breaking:** Replace bare session references with opaque, owner-aware
  handles and reject cross-process, closed, unknown, and phase-invalid use with
  `Decibel.SessionError`. **Migration:** treat handles as opaque, drop 0.2-era
  `is_reference/1` checks on session values, perform every operation serially
  in the process that called `new/4`, call `close/1` when finished, and create a
  new session after the owner exits.
- Make the raising API contract explicit: data-producing operations return
  their payload directly, state-only operations return `:ok`, and rejected
  operations raise stable exceptions without committing session state.
- **Breaking:** Enforce initiator-to-responder transport direction after the
  one-way `N`, `K`, and `X` handshakes. **Migration:** only the initiator may
  encrypt and only the responder may decrypt; choose an interactive pattern
  when the application needs bidirectional transport.
- **Breaking:** Reject attempts to move an outbound transport nonce backwards.
  **Migration:** read the next outbound value with `nonce/2`, leave it unchanged
  or move it forward only, and keep application-owned replay state when
  selecting inbound nonces with `set_nonce/3`.
- **Breaking:** Generate a fresh local ephemeral keypair for every ordinary
  handshake and reject caller-supplied ephemeral keys outside fallback
  pre-messages. **Migration:** omit `:e` and `:re` for ordinary handshakes and
  supply them only for their role-specific fallback pre-message within the
  same Noise Pipes run.
- **Breaking:** Enforce Noise's 65,535-byte limit for handshake and transport
  messages. Transport plaintexts are limited to 65,519 bytes to leave room for
  the authentication tag. **Migration:** split larger logical messages and
  preserve and authenticate Noise message boundaries in application framing.
- Make connectionless replay protection explicitly application-owned, with a
  bounded replay-window example that records nonces only after successful
  authentication and guidance for coordinated rekeying.
- Correct handshake-hash, Diffie-Hellman keypair, and nonce types so HexDocs
  accurately describes 32- and 64-byte hashes, stored keypairs, usable nonce
  bounds, and the reserved exhaustion value.

### Removed

- **Breaking:** Remove the unsupported custom `:registry` construction option.
  **Migration:** select a supported Noise r34 pattern from Decibel's built-in
  registry; `:swap` remains available for interactive fallback handshakes.

### Fixed

- Validate all role-specific static key material, fallback ephemerals, prologue
  data, and construction options during session creation, raising stable
  field-level errors before storing session state. Configurations that
  previously failed later must now provide exactly the key material required by
  the selected role and fully modified pattern.
- Reject malformed or non-canonical Noise protocol names, invalid modifier
  placements, and missing, malformed, or unused pre-shared keys during session
  creation instead of silently omitting PSK authentication.
- Return `Decibel.DecryptionError` with a stable reason for truncated,
  unauthenticated, or invalid-key peer messages, preserving processed remote
  keys and leaving session state unchanged.
- Allow Noise's final usable transport nonce (`2^64 - 2`) once, then raise
  `Decibel.NonceError` on exhaustion; `set_nonce/3` now rejects reserved,
  negative, non-integer, and oversized nonce values without changing session
  state.

## 0.2.4 - Jan 22, 2025

- Update deps
- Fix compiler errors

## 0.2.3 - June 6, 2023

- Fix unused alias warning.

## 0.2.2 - June 6, 2023

- Add `get_remote_key/1` to the public API.

## 0.2.1 - June 6, 2023 (Reverted)

- Add `get_public_key/2` to the public API.

## 0.2.0 - May 19, 2023
- Breaking change - renamed `set_n/3` and `get_n/2` to `set_nonce/3`
  and `get_nonce/2` respectively
- AEAD failure now raises a `Decibel.DecryptionError` rather than
  a `RuntimeError`. If this is raised during a handshake, this struct 
  will also contain any remote public keys processed during the
  handshake, up to the point of failure
- Added fallback tests
- Improved documentation around Noise Pipes and connectionless
  transports

## 0.1.1 - April 25, 2023

- Initial revision
