# Connectionless Transports

Once the handshake completes, Noise provides support for the encryption and
decryption of messages over connectionless i.e. potentially _unordered_,
potentially _lossy_ transports, and Decibel honours this support. For one-way
patterns, the sender uses only the outbound operations and the recipient uses
only the inbound operations shown below.

> #### Danger: replay and nonce reuse {: .warning}
>
> A recipient using `Decibel.set_nonce/3` must track every nonce that decrypted
> successfully and reject duplicates; otherwise an attacker can replay an
> authenticated message. An outbound nonce must never be reused with the same
> key. `Decibel.ReplayWindow` provides the bookkeeping value, but the
> application still owns, stores, and serializes it; Decibel does not hide
> replay state in the session or provide a replay-protected decrypt operation.

The sender and recipient sessions stay in their respective owner processes.
Transfer `{nonce, ciphertext, aad}` between processes or peers, not either
session handle. Each owner must serialize its session operations with updates
to its application-owned replay window.

A sender reads the nonce that `Decibel.encrypt/3` will consume and sends it
alongside the ciphertext:

```elixir
nonce = Decibel.nonce(sender, :out)
ciphertext = Decibel.encrypt(sender, plaintext, aad)
send(peer, {nonce, ciphertext})
```

Choose replay handling to match the transport:

- Reliable, ordered transports use the cipher's implicit nonce progression and
  need neither `Decibel.set_nonce/3` nor a replay window.
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
    with :ok <- Decibel.ReplayWindow.check(window, nonce),
         :ok <- Decibel.set_nonce(ref, :in, nonce) do
      try do
        plaintext = Decibel.decrypt(ref, ciphertext, aad)
        {:ok, plaintext, Decibel.ReplayWindow.commit(window, nonce)}
      rescue
        error in Decibel.DecryptionError -> {:error, error, window}
      end
    else
      {:error, reason} -> {:error, reason, window}
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
nonce = Decibel.nonce(sender, :out)
aad = <<nonce::unsigned-little-64>>
ciphertext = Decibel.encrypt(sender, "connectionless packet", aad)

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

The window changes only after authentication succeeds. A failed ciphertext
therefore does not prevent a later authentic packet with the same nonce from
being tried.

See the
[nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying)
for the application responsibilities around `Decibel.rekey/2`.
