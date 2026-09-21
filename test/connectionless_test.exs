defmodule Decibel.ConnectionlessTest do
  use ExUnit.Case

  alias Decibel.ReplayWindow

  @moduletag :connectionless
  @guide_path Path.expand("../guides/connectionless-transports.md", __DIR__)
  @reserved_nonce 2 ** 64 - 1
  @past_reserved_nonce 2 ** 64

  setup_all do
    assert {"connectionless packet", binding} =
             @guide_path
             |> connectionless_example()
             |> Code.eval_string([], file: @guide_path)

    {:ok, decrypt_connectionless: Keyword.fetch!(binding, :decrypt_connectionless)}
  end

  for {name, protocol, mode} <- [
        {"interactive ChaChaPoly/25519/BLAKE2s", "Noise_NN_25519_ChaChaPoly_BLAKE2s", :interactive},
        {"one-way AESGCM/448/SHA512", "Noise_N_448_AESGCM_SHA512", :one_way}
      ] do
    test "#{name} rejects connectionless replays after authentication", %{
      decrypt_connectionless: decrypt_connectionless
    } do
      {sender, recipient} = establish_session(unquote(protocol), unquote(mode))

      packets =
        for nonce <- 0..65, into: %{} do
          assert nonce == Decibel.nonce(sender, :out)
          aad = <<nonce::unsigned-little-64>>
          ciphertext = Decibel.encrypt(sender, "packet #{nonce}", aad)
          {nonce, {ciphertext, aad}}
        end

      window = ReplayWindow.new()
      {ciphertext65, aad65} = packets[65]

      assert {:ok, "packet 65", window} =
               decrypt_connectionless.(recipient, 65, ciphertext65, aad65, window)

      {ciphertext2, aad2} = packets[2]

      assert {:ok, "packet 2", window} =
               decrypt_connectionless.(recipient, 2, ciphertext2, aad2, window)

      recipient_nonce = Decibel.nonce(recipient, :in)

      assert {:error, :duplicate, ^window} =
               decrypt_connectionless.(recipient, 65, ciphertext65, aad65, window)

      {ciphertext1, aad1} = packets[1]

      assert {:error, :stale, ^window} =
               decrypt_connectionless.(recipient, 1, ciphertext1, aad1, window)

      assert Decibel.nonce(recipient, :in) == recipient_nonce

      {ciphertext3, aad3} = packets[3]
      tampered3 = flip_first_bit(ciphertext3)

      assert {:error, %Decibel.DecryptionError{reason: :authentication_failed}, ^window} =
               decrypt_connectionless.(recipient, 3, tampered3, aad3, window)

      assert :ok == ReplayWindow.check(window, 3)

      assert {:ok, "packet 3", window} =
               decrypt_connectionless.(recipient, 3, ciphertext3, aad3, window)

      recipient_nonce = Decibel.nonce(recipient, :in)

      for invalid <- [-1, @reserved_nonce, @past_reserved_nonce, :not_a_nonce] do
        assert_raise ArgumentError, fn ->
          decrypt_connectionless.(recipient, invalid, ciphertext3, aad3, window)
        end

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
               decrypt_connectionless.(recipient, nonce66, ciphertext66, aad66, window)

      assert {:error, :duplicate, ^window} =
               decrypt_connectionless.(recipient, 65, ciphertext65, aad65, window)

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

  defp connectionless_example(path) do
    pattern =
      ~r/<!-- connectionless-example:start -->\s*```elixir\n(?<code>.*?)\n```\s*<!-- connectionless-example:end -->/s

    %{"code" => code} = Regex.named_captures(pattern, File.read!(path))
    code
  end
end
