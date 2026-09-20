# Decibel

Decibel is an Elixir implementation of the [Noise Protocol Framework](https://noiseprotocol.org/).

## Security posture

Decibel implements
[Noise revision 34](https://noiseprotocol.org/noise.html). Revision 34 is marked
`official/unstable`; its
[change log](https://noiseprotocol.org/noise.html#change-log) says the unstable
marking applies only to the new deferred patterns. Decibel supports all r34
one-way, fundamental, and deferred patterns, plus applicable `pskN` and
`fallback` modifiers, with `25519` and `448` DH, `ChaChaPoly` and `AESGCM`
ciphers, and `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b` hashes.

The test suite includes known-answer vectors from
[Cacophony](https://github.com/haskell-cryptography/cacophony),
[Snow](https://github.com/mcginty/snow), and
[noise-c](https://github.com/rweather/noise-c). These are interoperability
evidence, not a security audit. Decibel has not received an independent security
audit or formal verification, is still pre-1.0, and has not been declared
production-ready. The package requires Elixir `~> 1.18` and uses Erlang/OTP's
`:crypto` implementation rather than a pluggable crypto backend.

## Safe use

Before using Decibel, applications must:

- choose a pattern and primitives for their threat model, then
  [authenticate any remote static key](https://noiseprotocol.org/noise.html#security-considerations)
  using certificates, an allow list, pinning, or another trust policy;
- follow the specification's
  [key-reuse rules](https://noiseprotocol.org/noise.html#security-considerations)
  by keeping static keys and PSKs inside Noise and one hash algorithm, provision
  PSKs with the required
  [256 bits of entropy](https://noiseprotocol.org/noise.html#security-considerations),
  and
  [never reuse ephemeral keys](https://noiseprotocol.org/noise.html#security-considerations);
- bind protocol/version negotiation into the `:prologue` or protect it
  equivalently against
  [rollback](https://noiseprotocol.org/noise.html#security-considerations);
- frame each Noise message and authenticate stream length or termination to
  detect
  [truncation](https://noiseprotocol.org/noise.html#application-responsibilities);
- [never reuse an outbound key/nonce pair](https://noiseprotocol.org/noise.html#security-considerations),
  [coordinate rekeying](https://noiseprotocol.org/noise.html#rekey), and provide
  a [replay window](https://noiseprotocol.org/noise.html#out-of-order-transport-messages)
  when selecting inbound nonces for connectionless transport; and
- define a [failure policy](https://noiseprotocol.org/noise.html#processing-rules)
  that discards unauthenticated data and decides when to abandon a handshake or
  transport session.

Decibel does not provide transport I/O, framing, negotiation, peer trust, key
storage or secure erasure, payload parsing/padding, or connectionless replay
state. Read the canonical
[HexDocs security guidance](https://hexdocs.pm/decibel/Decibel.html#module-security-posture)
before integrating it. Report vulnerabilities according to
[`SECURITY.md`](SECURITY.md).

## Installation

The package can be installed by adding `decibel` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:decibel, "~> 0.2.0"}
  ]
end
```

Documentation can be found at <https://hexdocs.pm/decibel>.

## Development

Run `mix precommit` before committing. Release-focused CI also requires
warning-free Dialyzer and ExDoc runs, an exact Hex package manifest, clean Hex
dependency audits, and at least 97% total line coverage;
`MIX_ENV=test mix coveralls` exits non-zero below that floor.
