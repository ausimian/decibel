# Noise Pipes

[Noise Pipes](http://www.noiseprotocol.org/noise.html#noise-pipes) are compound
protocols combining:

- A full handshake (e.g. `XX`)
- A zero-RTT handshake (e.g. `IK`)
- A fallback handshake (e.g. `XXfallback`)

The specification provides more detail on Noise Pipes, as does the
[Wiki](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors#noise-pipes).
Decibel provides support for all these individual protocols and the necessary
information to transition between a failed IK handshake and the fallback.
The failed session and its replacement fallback session must be created and
operated by the same owner process. Pass the failed ciphertext to that owner;
do not pass its session handle to a separate fallback worker.

## Decryption Errors

Malformed peer messages raise `Decibel.DecryptionError`. Its `:reason` field is
the stable error contract: `:truncated` identifies an incomplete key field or
authentication tag, `:authentication_failed` identifies failed AEAD
verification, and `:invalid_public_key` identifies a peer DH key rejected by
the selected curve. The exception message remains `"Decryption failed"` for
every reason.

During a handshake, the error's `:remote_keys` field contains any remote public
keys processed up to the point of failure. Failed operations do not update the
stored handshake state or advance a transport nonce.

## Example

The following example shows a responder handling the decryption failure, and
then transitioning to the fallback protocol, using the remote ephemeral key,
via `Noise_XXfallback_25519_ChaChaPoly_BLAKE2b`.

```elixir
# Process IK handshake message sent by the initiator
try do
  _ = Decibel.handshake_decrypt(rsp, ciphertext)
  # Happy path continues here...
rescue
  e in Decibel.DecryptionError ->
    # Grab the remote ephemeral key sent by the initiator during the failed
    # handshake
    re = e.remote_keys[:re]
    # Now construct the new responder for the fallback protocol
    rsp = Decibel.new(
      "Noise_XXfallback_25519_ChaChaPoly_BLAKE2b",
      :rsp,
      %{re: re, s: responder_static},
      swap: :rsp
    )
    # Start the new handshake (not shown) ...
end
```

Note that although the code reconstructs the responder, as the handshake is a
fallback protocol, the code is _effectively_ the initiator, and will send the
first message on this new handshake.

The failed initiator's original ephemeral is the fallback pre-message input on
both sides. The original initiator supplies its local keypair as `:e`; the
responder shown above retrieves the public key from the error and supplies it
as `:re`. These keys are prior transcript input and are not transmitted again
by the fallback handshake.

- The retrieval of the remote ephemeral (`re`) key from the error
- The prepopulation of that key as `:re` in the responder's new handshake
  (other keys omitted for brevity)
- The use of the `[swap: :rsp]` option - this is required to ensure the split
  cipher channels are correctly paired after the interactive fallback
  handshake. The `swap:` option affects only interactive handshakes; it never
  reverses the permitted direction of a one-way handshake.
