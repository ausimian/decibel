defmodule Decibel.DecryptionErrorTest do
  use ExUnit.Case

  alias Decibel.{Crypto, DecryptionError}

  @suites [
    %{
      name: "25519 ChaChaPoly BLAKE2s",
      curve: :x25519,
      curve_name: "25519",
      dh_len: 32,
      cipher: "ChaChaPoly",
      hash: "BLAKE2s"
    },
    %{
      name: "448 AESGCM SHA512",
      curve: :x448,
      curve_name: "448",
      dh_len: 56,
      cipher: "AESGCM",
      hash: "SHA512"
    }
  ]

  test "truncation at every XX field boundary preserves state and key context" do
    for suite <- @suites do
      ini_static = Crypto.generate_keypair(suite.curve)
      rsp_static = Crypto.generate_keypair(suite.curve)
      ini = Decibel.new(protocol("XX", suite), :ini, %{s: ini_static})
      rsp = Decibel.new(protocol("XX", suite), :rsp, %{s: rsp_static})

      message1 = ini |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      ini_ephemeral = binary_part(message1, 0, suite.dh_len)

      assert byte_size(message1) == suite.dh_len

      assert_truncated_prefixes(rsp, message1, fn _length ->
        [re: nil, rs: nil]
      end)

      assert "" == Decibel.handshake_decrypt(rsp, message1)

      message2 = rsp |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      rsp_ephemeral = binary_part(message2, 0, suite.dh_len)
      rsp_static_public = elem(rsp_static, 0)
      static_end = 2 * suite.dh_len + 16

      assert byte_size(message2) == static_end + 16

      assert_truncated_prefixes(ini, message2, fn length ->
        cond do
          length < suite.dh_len -> [re: nil, rs: nil]
          length < static_end -> [re: rsp_ephemeral, rs: nil]
          true -> [re: rsp_ephemeral, rs: rsp_static_public]
        end
      end)

      assert_failure(
        ini,
        flip_byte(message2, static_end - 1),
        :authentication_failed,
        re: rsp_ephemeral,
        rs: nil
      )

      assert_failure(
        ini,
        flip_byte(message2, byte_size(message2) - 1),
        :authentication_failed,
        re: rsp_ephemeral,
        rs: rsp_static_public
      )

      assert "" == Decibel.handshake_decrypt(ini, message2)

      message3 = ini |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      ini_static_public = elem(ini_static, 0)
      encrypted_static_end = suite.dh_len + 16

      assert byte_size(message3) == encrypted_static_end + 16

      assert_truncated_prefixes(rsp, message3, fn length ->
        if length < encrypted_static_end do
          [re: ini_ephemeral, rs: nil]
        else
          [re: ini_ephemeral, rs: ini_static_public]
        end
      end)

      assert "" == Decibel.handshake_decrypt(rsp, message3)
      assert Decibel.is_handshake_complete?(ini)
      assert Decibel.is_handshake_complete?(rsp)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "truncation at unkeyed static fields preserves state and key context" do
    for suite <- @suites do
      ini_static = Crypto.generate_keypair(suite.curve)
      ini = Decibel.new(protocol("IN", suite), :ini, %{s: ini_static})
      rsp = Decibel.new(protocol("IN", suite), :rsp)

      message = ini |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      ini_ephemeral = binary_part(message, 0, suite.dh_len)

      assert byte_size(message) == 2 * suite.dh_len

      assert_truncated_prefixes(rsp, message, fn length ->
        if length < suite.dh_len do
          [re: nil, rs: nil]
        else
          [re: ini_ephemeral, rs: nil]
        end
      end)

      assert "" == Decibel.handshake_decrypt(rsp, message)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "invalid peer public keys raise stable errors for both DH functions" do
    for suite <- @suites do
      {rsp_public, _rsp_private} = rsp_static = Crypto.generate_keypair(suite.curve)
      ini = Decibel.new(protocol("N", suite), :ini, %{rs: rsp_public})
      rsp = Decibel.new(protocol("N", suite), :rsp, %{s: rsp_static})
      valid_message = ini |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      invalid_key = :binary.copy(<<0>>, suite.dh_len)

      assert_failure(rsp, invalid_key, :invalid_public_key, re: invalid_key, rs: nil)
      assert "" == Decibel.handshake_decrypt(rsp, valid_message)
      assert Decibel.is_handshake_complete?(ini)
      assert Decibel.is_handshake_complete?(rsp)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "a delayed invalid peer key failure does not commit response state" do
    suite = hd(@suites)
    rsp = Decibel.new(protocol("NN", suite), :rsp)
    invalid_key = :binary.copy(<<0>>, suite.dh_len)

    assert "" == Decibel.handshake_decrypt(rsp, invalid_key)

    error =
      assert_raise DecryptionError, "Decryption failed", fn ->
        Decibel.handshake_encrypt(rsp)
      end

    assert error.reason == :invalid_public_key
    assert error.remote_keys == [re: invalid_key, rs: nil]

    retry_error =
      assert_raise DecryptionError, "Decryption failed", fn ->
        Decibel.handshake_encrypt(rsp)
      end

    assert retry_error.reason == error.reason
    assert retry_error.remote_keys == error.remote_keys

    Decibel.close(rsp)
  end

  test "short and unauthenticated transport ciphertexts preserve state and nonce" do
    for suite <- @suites do
      {ini, rsp} = establish_session(suite)
      valid_message = ini |> Decibel.encrypt("valid transport") |> IO.iodata_to_binary()

      for length <- 0..15 do
        error =
          assert_raise DecryptionError, "Decryption failed", fn ->
            Decibel.decrypt(rsp, :binary.copy(<<0>>, length))
          end

        assert error.reason == :truncated
        assert error.remote_keys == []
        assert Decibel.get_nonce(rsp, :in) == 0
      end

      error =
        assert_raise DecryptionError, "Decryption failed", fn ->
          Decibel.decrypt(rsp, flip_byte(valid_message, 0))
        end

      assert error.reason == :authentication_failed
      assert error.remote_keys == []
      assert Decibel.get_nonce(rsp, :in) == 0

      assert "valid transport" == Decibel.decrypt(rsp, valid_message)
      assert Decibel.get_nonce(rsp, :in) == 1

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  defp assert_truncated_prefixes(ref, message, remote_keys) do
    for length <- 0..(byte_size(message) - 1) do
      error =
        assert_raise DecryptionError, "Decryption failed", fn ->
          Decibel.handshake_decrypt(ref, binary_part(message, 0, length))
        end

      assert error.reason == :truncated
      assert error.remote_keys == remote_keys.(length)
    end
  end

  defp assert_failure(ref, message, reason, remote_keys) do
    error =
      assert_raise DecryptionError, "Decryption failed", fn ->
        Decibel.handshake_decrypt(ref, message)
      end

    assert error.reason == reason
    assert error.remote_keys == remote_keys
  end

  defp establish_session(suite) do
    ini = Decibel.new(protocol("NN", suite), :ini)
    rsp = Decibel.new(protocol("NN", suite), :rsp)

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    rsp
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(ini, &1))

    {ini, rsp}
  end

  defp protocol(pattern, suite) do
    "Noise_#{pattern}_#{suite.curve_name}_#{suite.cipher}_#{suite.hash}"
  end

  defp flip_byte(message, index) do
    <<prefix::binary-size(^index), byte, suffix::binary>> = message
    <<prefix::binary, Bitwise.bxor(byte, 1), suffix::binary>>
  end
end
