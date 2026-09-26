# Getting Started

## Installation

The package can be installed by adding `decibel` to your list of dependencies
in `mix.exs`:

```elixir
def deps do
  [
    {:decibel, "~> 1.0"}
  ]
end
```

Documentation can be found at <https://hexdocs.pm/decibel>.

## Getting started

Read the [security guidance](security.md) before choosing a protocol for a real
application. These examples keep both peers in one IEx process so they are easy
to run. Real peers should follow `m:Decibel#module-lifecycle` for session
ownership and message exchange.

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

See the [framing guidance](security.md#framing-payloads-and-termination) for
application responsibilities and `m:Decibel#module-api-conventions` for
Decibel's iodata contract.

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
`Decibel.remote_key/1` with an independently trusted value before accepting
that peer. See
[Authentication and key handling](security.md#authentication-and-key-handling).

## Usage recipes

### Patterns and static keys

Choose a pattern using the
[pattern and primitive guidance](security.md#pattern-and-primitive-selection).
Generate X25519 static keypairs with `:crypto.generate_key(:ecdh, :x25519)` and
provision them as `:s`; patterns with a remote static pre-message also require
the trusted public key as `:rs`. Follow the
[authentication and key-handling guidance](security.md#authentication-and-key-handling)
for key reuse and trust validation.

### Pre-shared keys

After generating a suitable PSK as described in the
[key-handling guidance](security.md#authentication-and-key-handling), provision
the same secret to both peers, select a PSK modifier, and pass PSKs in modifier
order:

```elixir
psk = :crypto.strong_rand_bytes(32)
protocol = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
initiator = Decibel.new(protocol, :ini, %{psks: [psk]})
responder = Decibel.new(protocol, :rsp, %{psks: [psk]})
```

### Handshake payloads

Pass a payload as the second argument to `Decibel.handshake_encrypt/2`; its peer
receives that payload from `Decibel.handshake_decrypt/2`. Consult the pattern's
[payload security properties](https://noiseprotocol.org/noise.html#payload-security-properties)
first: early handshake payloads can be cleartext or have weaker authentication
than the completed channel.

### Channel binding

After both handshakes complete, `Decibel.handshake_hash/1` returns the
channel-binding value. Both peers should obtain the same non-`nil` value; bind
it into the application's higher-level authentication protocol where required.
See the Noise
[channel-binding guidance](https://noiseprotocol.org/noise.html#channel-binding).

### Rekeying

Coordinate rekeying by changing the sender's `:out` key and the recipient's
matching `:in` key:

```elixir
:ok = Decibel.rekey(sender, :out)
:ok = Decibel.rekey(recipient, :in)
```

Follow the
[nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying)
for counter, replay-window, and delayed-message handling.

### Fallback and connectionless delivery

For Noise Pipes, including the parser-valid
`Noise_XXfallback_25519_ChaChaPoly_BLAKE2b` protocol, follow the complete
[fallback example](noise-pipes.md). For unordered or lossy delivery, send the
`{nonce, ciphertext}` returned by `Decibel.encrypt_with_nonce/3` and use the
[bounded replay-window example](connectionless-transports.md); Decibel exposes
nonce selection but the application owns replay rejection.

### Ownership, cleanup, and errors

Follow `m:Decibel#module-lifecycle` for session ownership and cleanup,
`m:Decibel#module-api-conventions` for the exception contract, and
[Failure handling](security.md#failure-handling) for application policy.
