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
audit or formal verification and has not been declared production-ready. The
package requires Elixir `~> 1.18` and uses Erlang/OTP's
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
    {:decibel, "~> 1.0"}
  ]
end
```

Documentation can be found at <https://hexdocs.pm/decibel>.

## Getting started

Read the [security posture](#security-posture) before choosing a protocol for a
real application. These examples keep both peers in one IEx process so they are
easy to run. In production, each peer process must create and serially operate
its own session; exchange framed Noise messages between processes, never
session handles.

### Unauthenticated NN

`NN` establishes an encrypted channel without static-key authentication. The
example also supplies a two-byte big-endian length prefix. That prefix is
application framing, not part of the Noise message or Decibel's wire format.

<!-- quickstart:nn:start -->
```elixir
protocol = "Noise_NN_25519_ChaChaPoly_BLAKE2s"
initiator = Decibel.new(protocol, :ini)
responder = Decibel.new(protocol, :rsp)

frame = fn noise_message ->
  message = IO.iodata_to_binary(noise_message)
  <<byte_size(message)::unsigned-big-16, message::binary>>
end

unframe = fn <<size::unsigned-big-16, message::binary-size(size)>> -> message end

packet1 = initiator |> Decibel.handshake_encrypt() |> frame.()
"" = Decibel.handshake_decrypt(responder, unframe.(packet1))

packet2 = responder |> Decibel.handshake_encrypt() |> frame.()
"" = Decibel.handshake_decrypt(initiator, unframe.(packet2))
true = Decibel.handshake_complete?(initiator)
true = Decibel.handshake_complete?(responder)

packet3 = initiator |> Decibel.encrypt("hello") |> frame.()
"hello" = Decibel.decrypt(responder, unframe.(packet3))

max_plaintext = :binary.copy(<<0>>, 65_519)
max_message = initiator |> Decibel.encrypt(max_plaintext) |> IO.iodata_to_binary()
65_535 = byte_size(max_message)
max_packet = frame.(max_message)
<<65_535::unsigned-big-16, _::binary-size(65_535)>> = max_packet
^max_plaintext = Decibel.decrypt(responder, unframe.(max_packet))

:ok = Decibel.close(initiator)
:ok = Decibel.close(responder)
```
<!-- quickstart:nn:end -->

A complete Noise message is limited to 65,535 bytes. The 16-byte transport
authentication tag leaves at most 65,519 plaintext bytes, so split larger
logical messages before encryption. Stream transports must preserve each Noise
message boundary and authenticate application length or termination semantics
to detect truncation.

Plaintext, associated data, and inbound messages accept iodata. Decibel's
message-producing calls return iodata; normalize it with
`IO.iodata_to_binary/1` before byte-oriented framing or I/O. Binary values are
valid iodata, and callers should not depend on an incidental list or binary
shape for returned payloads.

### Authenticated IK

`IK` lets the initiator authenticate a responder static key it already trusts,
and lets the responder authenticate the initiator's static key from the first
handshake message.

<!-- quickstart:ik:start -->
```elixir
protocol = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
{initiator_public, _initiator_private} = initiator_static = :crypto.generate_key(:ecdh, :x25519)
{responder_public, _responder_private} = responder_static = :crypto.generate_key(:ecdh, :x25519)

# In a real system these come from certificates, an allow list, pinning, or
# another trust policy independent of this handshake.
trusted_initiator_key = initiator_public
trusted_responder_key = responder_public

initiator =
  Decibel.new(protocol, :ini, %{s: initiator_static, rs: trusted_responder_key})

responder = Decibel.new(protocol, :rsp, %{s: responder_static})

message1 = Decibel.handshake_encrypt(initiator)
"" = Decibel.handshake_decrypt(responder, message1)
^trusted_initiator_key = Decibel.remote_key(responder)

message2 = Decibel.handshake_encrypt(responder)
"" = Decibel.handshake_decrypt(initiator, message2)
^trusted_responder_key = Decibel.remote_key(initiator)

ciphertext = Decibel.encrypt(initiator, "authenticated hello")
"authenticated hello" = Decibel.decrypt(responder, ciphertext)

:ok = Decibel.close(initiator)
:ok = Decibel.close(responder)
```
<!-- quickstart:ik:end -->

Noise authenticates possession of static keys according to the selected
pattern; it does not decide whether a key belongs to the intended peer. Compare
`remote_key/1` with an independently trusted value before accepting that peer.

## Usage recipes

### Patterns and static keys

Choose a pattern whose
[payload security properties](https://noiseprotocol.org/noise.html#payload-security-properties)
fit the application's authentication, identity-hiding, forward-secrecy, and
latency requirements. Generate X25519 static keypairs with
`:crypto.generate_key(:ecdh, :x25519)` and provision them as `:s`; patterns
with a remote static pre-message also require the trusted public key as `:rs`.
Follow Decibel's
[authentication and key-handling guidance](https://hexdocs.pm/decibel/Decibel.html#module-authentication-and-key-handling)
for key reuse and trust validation.

### Pre-shared keys

Generate a 32-byte, 256-bit-entropy secret, provision the same secret to both
peers, select a PSK modifier, and pass PSKs in modifier order:

```elixir
psk = :crypto.strong_rand_bytes(32)
protocol = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
initiator = Decibel.new(protocol, :ini, %{psks: [psk]})
responder = Decibel.new(protocol, :rsp, %{psks: [psk]})
```

Passwords and low-entropy tokens are not PSKs. Keep each PSK within Noise and
one hash algorithm as described in the linked key-handling guidance.

### Handshake payloads

Pass a payload as the second argument to `handshake_encrypt/2`; its peer
receives that payload from `handshake_decrypt/2`. Consult the pattern's
[payload security properties](https://noiseprotocol.org/noise.html#payload-security-properties)
first: early handshake payloads can be cleartext or have weaker authentication
than the completed channel.

### Channel binding

After both handshakes complete, `handshake_hash/1` returns the channel-binding
value. Both peers should obtain the same non-`nil` value; bind it into the
application's higher-level authentication protocol where required. See the
Noise [channel-binding guidance](https://noiseprotocol.org/noise.html#channel-binding).

### Rekeying

Coordinate rekeying by changing the sender's `:out` key and the recipient's
matching `:in` key:

```elixir
:ok = Decibel.rekey(sender, :out)
:ok = Decibel.rekey(recipient, :in)
```

Rekeying does not reset nonces or connectionless replay windows, and delayed
messages under the old key will no longer decrypt. Coordinate each direction
independently.

### Fallback and connectionless delivery

For Noise Pipes, including the parser-valid
`Noise_XXfallback_25519_ChaChaPoly_BLAKE2b` protocol, follow the complete
[fallback example](https://hexdocs.pm/decibel/Decibel.html#module-noise-pipes).
For unordered or lossy delivery, send `{nonce, ciphertext}` and use the
[bounded replay-window example](https://hexdocs.pm/decibel/Decibel.html#module-connectionless-transports);
Decibel exposes nonce selection but the application owns replay rejection.

### Ownership, cleanup, and errors

A session belongs to the process that called `new/4`. That process must
serialize every operation and should call `close/1` when finished. Owner exit
also discards the state automatically. Closed handles cannot be reused, and a
second close raises `Decibel.SessionError` with `reason: :closed`.

Construction and size errors raise `ArgumentError`; peer-message failures
raise `Decibel.DecryptionError`; nonce and one-way direction failures raise
`Decibel.NonceError` and `Decibel.TransportDirectionError`; ownership,
lifetime, and phase failures raise `Decibel.SessionError`. Rescue them only at
boundaries with an explicit recovery policy, and follow the central
[failure-handling guidance](https://hexdocs.pm/decibel/Decibel.html#module-failure-handling)
rather than exposing detailed failures to an untrusted peer.

## Development

Run `mix precommit` before committing. Release-focused CI also requires
warning-free Dialyzer and ExDoc runs, an exact Hex package manifest, clean Hex
dependency audits, and at least 97% total line coverage;
`MIX_ENV=test mix coveralls` exits non-zero below that floor.
