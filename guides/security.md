# Security

## Security posture

Decibel implements [Noise revision 34](https://noiseprotocol.org/noise.html).
Revision 34 is marked `official/unstable`; its
[change log](https://noiseprotocol.org/noise.html#change-log) says that the
unstable marking applies only to the new deferred patterns and that the rest
of the document is considered stable.

The built-in registry supports these handshake patterns:

- One-way: `N`, `K`, and `X`.
- Fundamental interactive: `NN`, `KN`, `NK`, `KK`, `NX`, `KX`, `XN`,
  `IN`, `XK`, `IK`, `XX`, and `IX`.
- Deferred interactive: `NK1`, `NX1`, `X1N`, `X1K`, `XK1`, `X1K1`,
  `X1X`, `XX1`, `X1X1`, `K1N`, `K1K`, `KK1`, `K1K1`, `K1X`, `KX1`,
  `K1X1`, `I1N`, `I1K`, `IK1`, `I1K1`, `I1X`, `IX1`, and `I1X1`.

Decibel also supports applicable `pskN` and `fallback` modifiers. Supported
primitives are:

- DH: `25519` (X25519) and `448` (X448).
- Cipher: `ChaChaPoly` (ChaCha20-Poly1305) and `AESGCM` (AES-256-GCM).
- Hash: `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`.

The test suite exercises checked-in known-answer vectors sourced from
[Cacophony](https://github.com/haskell-cryptography/cacophony),
[Snow](https://github.com/mcginty/snow), and
[noise-c](https://github.com/rweather/noise-c) fallback vectors. Passing
these vectors demonstrates interoperability for the tested inputs; it is not
a security audit or a guarantee about an application's surrounding protocol.

The package declares Elixir `~> 1.18`. CI currently tests Elixir 1.18 with
OTP 27, Elixir 1.19 with OTP 27 and 28, and Elixir 1.20 with OTP 27 through
29 on Linux and macOS. Cryptographic operations use Erlang/OTP's `:crypto`
application. Decibel has no pluggable crypto provider, so the implementation
and availability of these primitives depend on the OTP installation.

> #### Security review and production use {: .warning}
>
> Decibel has not received an independent security audit or formal
> verification and has not been declared production-ready.
> Applications considering production use must review Decibel and their
> complete protocol, key management, failure policy, and deployment against
> their own threat model.

Decibel's non-goals include transport I/O, message framing, protocol
negotiation, peer identity or trust policy, long-term key storage, secure
memory erasure, application payload parsing or padding, and connectionless
replay state.

## Safe use

### Pattern and primitive selection

Select a handshake pattern whose
[payload security properties](https://noiseprotocol.org/noise.html#payload-security-properties)
match the application's authentication, identity-hiding, forward-secrecy, and
latency requirements.

Noise's
[application responsibilities](https://noiseprotocol.org/noise.html#application-responsibilities)
recommend `25519` for typical use and say `448` should be paired with a
512-bit hash such as `SHA512` or `BLAKE2b`. The specification also limits
[AESGCM data under one key](https://noiseprotocol.org/noise.html#security-considerations)
to 2^56 bytes; choose another cipher or re-handshake before that bound could
be reached.

### Authentication and key handling

A pattern containing static keys proves possession only where that pattern's
security properties say it does. The application must decide whether a
remote static key is acceptable, for example through a certificate,
configured allow list, pinning, or key continuity. See the specification's
[authentication guidance](https://noiseprotocol.org/noise.html#security-considerations)
and authenticate the value available through `Decibel.remote_key/1`.

The specification's
[key-reuse rules](https://noiseprotocol.org/noise.html#security-considerations)
require a Noise static keypair to stay within Noise and one hash algorithm.
A PSK must likewise stay within Noise and one hash algorithm, and must be a
secret value with 256 bits of entropy. Decibel verifies that each PSK is 32
bytes, but cannot verify its entropy or provenance; passwords and
low-entropy tokens are not suitable PSKs. For every reused secret, the
protocol name must uniquely identify the handshake pattern and cryptographic
operations performed with that key.

Every ordinary handshake generates a fresh local ephemeral keypair when its
outbound `e` token is processed. Caller-supplied `:e` and `:re` values are
accepted only for their corresponding fallback pre-messages. That reuse is
part of the same compound-protocol run and does not make ephemeral reuse
between sessions safe. The r34
[ephemeral-key rule](https://noiseprotocol.org/noise.html#security-considerations)
warns that reuse is likely to cause catastrophic key reuse.

### Negotiation and rollback

Decibel does not negotiate protocol names, versions, roles, or application
capabilities. If peers communicate negotiation data before the handshake,
include a canonical encoding of that context in the same `:prologue` at both
peers, or authenticate it through an equivalent higher-level design. The r34
[rollback guidance](https://noiseprotocol.org/noise.html#security-considerations)
warns that negotiation not included in the prologue can permit downgrade
attacks.

### Framing, payloads, and termination

Each Decibel handshake or transport operation processes exactly one Noise
message. The application must frame message boundaries and enforce the
65,535-byte Noise message limit. It must also authenticate length or
termination information inside its payload protocol so an attacker cannot
silently truncate a transport stream. Noise's
[application responsibilities](https://noiseprotocol.org/noise.html#application-responsibilities)
discuss framing, truncation, extensible payloads, and padding.

### Nonces, replay protection, and rekeying

Never encrypt two messages under the same key and nonce. Decibel increments
outbound nonces, rejects outbound rewinds, and raises `Decibel.NonceError`
at exhaustion. For connectionless transport, `Decibel.set_nonce/3` selects an
inbound nonce but does not provide replay protection. The application must
retain a bounded replay window, reject every nonce that has already
authenticated, and record a nonce only after successful decryption. See
[Connectionless Transports](connectionless-transports.md) for a complete
example and the specification's
[out-of-order transport guidance](https://noiseprotocol.org/noise.html#out-of-order-transport-messages).

`Decibel.rekey/2` changes one directional key without resetting its nonce.
Peers must coordinate rekeying independently in each direction, preserve their
nonce and replay state, and expect delayed packets under the old key to fail.
Close the session and perform a new handshake after nonce exhaustion. See the
specification's [rekey guidance](https://noiseprotocol.org/noise.html#rekey).

### Failure handling

Abandon a failed handshake unless the application is deliberately executing
a reviewed compound protocol such as Noise Pipes fallback. For a transport
authentication failure, discard the message and choose explicitly whether
the threat model calls for closing the session or continuing. The Noise
[processing rules](https://noiseprotocol.org/noise.html#processing-rules)
permit either transport policy; unauthenticated plaintext must never be used.
Do not expose detailed failure distinctions to an untrusted peer.

See `m:Decibel#module-api-conventions` for the exception taxonomy and rejected
operations' state guarantees.
