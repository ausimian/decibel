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

defmodule Decibel.ConnectionlessTest do
  use ExUnit.Case

  @moduletag :connectionless
  @reserved_nonce 2 ** 64 - 1
  @past_reserved_nonce 2 ** 64

  # Keep ConnectionlessReplayWindow identical to the module documentation's
  # Connectionless Transports example.
  for {name, protocol, mode} <- [
        {"interactive ChaChaPoly/25519/BLAKE2s", "Noise_NN_25519_ChaChaPoly_BLAKE2s", :interactive},
        {"one-way AESGCM/448/SHA512", "Noise_N_448_AESGCM_SHA512", :one_way}
      ] do
    test "#{name} rejects connectionless replays after authentication" do
      {sender, recipient} = establish_session(unquote(protocol), unquote(mode))

      packets =
        for nonce <- 0..65, into: %{} do
          assert nonce == Decibel.nonce(sender, :out)
          aad = <<nonce::unsigned-little-64>>
          ciphertext = Decibel.encrypt(sender, "packet #{nonce}", aad)
          {nonce, {ciphertext, aad}}
        end

      window = ConnectionlessReplayWindow.new()
      {ciphertext65, aad65} = packets[65]

      assert {:ok, "packet 65", window} =
               ConnectionlessReplayWindow.decrypt(recipient, 65, ciphertext65, aad65, window)

      {ciphertext2, aad2} = packets[2]

      assert {:ok, "packet 2", window} =
               ConnectionlessReplayWindow.decrypt(recipient, 2, ciphertext2, aad2, window)

      recipient_nonce = Decibel.nonce(recipient, :in)

      assert {:error, :duplicate, ^window} =
               ConnectionlessReplayWindow.decrypt(recipient, 65, ciphertext65, aad65, window)

      {ciphertext1, aad1} = packets[1]

      assert {:error, :stale, ^window} =
               ConnectionlessReplayWindow.decrypt(recipient, 1, ciphertext1, aad1, window)

      assert Decibel.nonce(recipient, :in) == recipient_nonce

      {ciphertext3, aad3} = packets[3]
      tampered3 = flip_first_bit(ciphertext3)

      assert {:error, %Decibel.DecryptionError{reason: :authentication_failed}, ^window} =
               ConnectionlessReplayWindow.decrypt(recipient, 3, tampered3, aad3, window)

      assert {:ok, "packet 3", window} =
               ConnectionlessReplayWindow.decrypt(recipient, 3, ciphertext3, aad3, window)

      recipient_nonce = Decibel.nonce(recipient, :in)

      for invalid <- [-1, @reserved_nonce, @past_reserved_nonce, :not_a_nonce] do
        error =
          assert_raise Decibel.NonceError, fn ->
            ConnectionlessReplayWindow.decrypt(recipient, invalid, ciphertext3, aad3, window)
          end

        assert error.reason == :out_of_range
        assert Decibel.nonce(recipient, :in) == recipient_nonce
      end

      sender_nonce = Decibel.nonce(sender, :out)
      recipient_nonce = Decibel.nonce(recipient, :in)
      assert :ok == Decibel.rekey(sender, :out)
      assert :ok == Decibel.rekey(recipient, :in)
      assert sender_nonce == Decibel.nonce(sender, :out)
      assert recipient_nonce == Decibel.nonce(recipient, :in)

      nonce66 = Decibel.nonce(sender, :out)
      aad66 = <<nonce66::unsigned-little-64>>
      ciphertext66 = Decibel.encrypt(sender, "packet after rekey", aad66)

      assert {:ok, "packet after rekey", window} =
               ConnectionlessReplayWindow.decrypt(recipient, nonce66, ciphertext66, aad66, window)

      assert {:error, :duplicate, ^window} =
               ConnectionlessReplayWindow.decrypt(recipient, 65, ciphertext65, aad65, window)

      Decibel.close(sender)
      Decibel.close(recipient)
    end
  end

  defp establish_session(protocol, :interactive) do
    ini = Decibel.new(protocol, :ini)
    rsp = Decibel.new(protocol, :rsp)

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    rsp
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(ini, &1))

    {ini, rsp}
  end

  defp establish_session(protocol, :one_way) do
    {rsp_public, _rsp_private} = rsp_static = :crypto.generate_key(:ecdh, :x448)
    ini = Decibel.new(protocol, :ini, %{rs: rsp_public})
    rsp = Decibel.new(protocol, :rsp, %{s: rsp_static})

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    {ini, rsp}
  end

  defp flip_first_bit(ciphertext) do
    <<first, rest::binary>> = IO.iodata_to_binary(ciphertext)
    <<Bitwise.bxor(first, 1), rest::binary>>
  end
end
