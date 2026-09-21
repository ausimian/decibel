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
> key. Decibel deliberately exposes a low-level nonce API and does not provide
> a replay-protected decrypt today, so the application owns this replay state.

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

The recipient needs a bounded replay window. This example retains the latest
64 nonce values. A nonce at the lower edge is accepted; older messages are
rejected as stale even if they were never received, keeping memory bounded.

```elixir
defmodule ConnectionlessReplayWindow do
  @moduledoc false
  @size 64
  @max_nonce 2 ** 64 - 2

  def new, do: %{highest: nil, seen: MapSet.new()}

  def decrypt(ref, nonce, ciphertext, aad, window) do
    :ok = validate_nonce(ref, nonce)

    cond do
      MapSet.member?(window.seen, nonce) ->
        {:error, :duplicate, window}

      stale?(window, nonce) ->
        {:error, :stale, window}

      true ->
        :ok = Decibel.set_nonce(ref, :in, nonce)

        try do
          plaintext = Decibel.decrypt(ref, ciphertext, aad)
          {:ok, plaintext, remember(window, nonce)}
        rescue
          error in Decibel.DecryptionError -> {:error, error, window}
        end
    end
  end

  defp validate_nonce(_ref, nonce)
       when is_integer(nonce) and nonce >= 0 and nonce <= @max_nonce,
       do: :ok

  defp validate_nonce(ref, nonce), do: Decibel.set_nonce(ref, :in, nonce)

  defp stale?(%{highest: nil}, _nonce), do: false
  defp stale?(%{highest: highest}, nonce), do: nonce <= highest - @size

  defp remember(window, nonce) do
    highest = max(window.highest || nonce, nonce)

    seen =
      window.seen
      |> MapSet.put(nonce)
      |> Enum.filter(&(&1 > highest - @size))
      |> MapSet.new()

    %{highest: highest, seen: seen}
  end
end

window = ConnectionlessReplayWindow.new()
{nonce, ciphertext} = get_msg_from(peer)

{:ok, plaintext, window} =
  ConnectionlessReplayWindow.decrypt(recipient, nonce, ciphertext, aad, window)

# A second delivery is rejected before Decibel decrypts it.
{:error, :duplicate, ^window} =
  ConnectionlessReplayWindow.decrypt(recipient, nonce, ciphertext, aad, window)
```

The window changes only after authentication succeeds. A failed ciphertext
therefore does not prevent a later authentic packet with the same nonce from
being tried.

See the
[nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying)
for the application responsibilities around `Decibel.rekey/2`.
