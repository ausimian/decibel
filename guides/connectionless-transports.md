# Connectionless Transports

Once the handshake completes, Noise provides support for the encryption and
decryption of messages over connectionless i.e. potentially _unordered_,
potentially _lossy_ transports, and Decibel honours this support. For one-way
patterns, the sender uses only the outbound operations and the recipient uses
only the inbound operations shown below.

> #### Danger: replay and nonce reuse {: .warning}
>
> A recipient that selects inbound nonces, with the `:nonce` option of
> `Decibel.decrypt/4` or with `Decibel.set_nonce/3`, must track every nonce
> that decrypted successfully and reject duplicates; otherwise an attacker can
> replay an authenticated message. An outbound nonce must never be reused with the same
> key. `Decibel.ReplayWindow` provides the bookkeeping value, but the
> application still owns, stores, and serializes it; Decibel does not hide
> replay state in the session or provide a replay-protected decrypt operation.

The sender and recipient sessions stay in their respective owner processes.
Transfer `{nonce, ciphertext, aad}` between processes or peers, not either
session handle. Each owner must serialize its session operations with updates
to its application-owned replay window.

A sender seals each message with `Decibel.encrypt_with_nonce/3`, which returns
the nonce it consumed, and sends that nonce alongside the ciphertext:

```elixir
{nonce, ciphertext} = Decibel.encrypt_with_nonce(sender, plaintext, aad)
send(peer, {nonce, ciphertext})
```

The recipient opens it at that nonce with
`Decibel.decrypt(recipient, ciphertext, aad, nonce: nonce)`. Each side makes one
session call per message.

The nonce is an input to the AEAD, so a ciphertext authenticates only at the
nonce it was sealed under, and the nonce need not be repeated in `aad`. A
protocol that does bind the nonce into its associated data must know it before
encrypting: read it with `Decibel.nonce/2`, then call `Decibel.encrypt/3`.

Choose replay handling to match the transport:

- Reliable, ordered transports use the cipher's implicit nonce progression and
  need neither explicit nonces nor a replay window.
- Lossy, in-order transports can retain only the highest authenticated nonce,
  rejecting nonces at or below it and updating it only after successful
  decryption.
- Lossy transports that can reorder messages use `Decibel.ReplayWindow`.

A replay window of size 64 retains exactly 64 nonce positions: `highest` down
to `highest - 63`. The next value, `highest - 64`, is stale even if it was never
received. This preserves the boundary used by the earlier bounded `MapSet`
example while replacing its storage with a bitmap.

<!-- connectionless-example:start -->
```elixir
defmodule ConnectionlessExample do
  @moduledoc false

  def decrypt(ref, nonce, ciphertext, aad, window) do
    case Decibel.ReplayWindow.check(window, nonce) do
      :ok ->
        try do
          plaintext = Decibel.decrypt(ref, ciphertext, aad, nonce: nonce)
          {:ok, plaintext, Decibel.ReplayWindow.commit(window, nonce)}
        rescue
          error in Decibel.DecryptionError -> {:error, error, window}
        end

      {:error, reason} ->
        {:error, reason, window}
    end
  end
end

decrypt_connectionless = &ConnectionlessExample.decrypt/5

sender = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
recipient = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

sender
|> Decibel.handshake_encrypt()
|> then(&Decibel.handshake_decrypt(recipient, &1))

recipient
|> Decibel.handshake_encrypt()
|> then(&Decibel.handshake_decrypt(sender, &1))

window = Decibel.ReplayWindow.new()
aad = "packet header"
{nonce, ciphertext} = Decibel.encrypt_with_nonce(sender, "connectionless packet", aad)

{:ok, plaintext, window} =
  decrypt_connectionless.(recipient, nonce, ciphertext, aad, window)

# A second delivery is rejected before Decibel decrypts it.
{:error, :duplicate, ^window} =
  decrypt_connectionless.(recipient, nonce, ciphertext, aad, window)

:ok = Decibel.close(sender)
:ok = Decibel.close(recipient)
plaintext
```
<!-- connectionless-example:end -->

The window changes only after authentication succeeds, and a failed decryption
leaves the session's inbound nonce unchanged. A failed ciphertext therefore does
not prevent a later authentic packet with the same nonce from being tried.

See the
[nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying)
for the application responsibilities around `Decibel.rekey/2`.
