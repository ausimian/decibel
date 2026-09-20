defmodule DecibelTest do
  use ExUnit.Case
  doctest Decibel

  @max_message_size 65_535
  @max_transport_plaintext_size @max_message_size - 16

  test "Simple NN Test" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, hs1)
    refute Enum.any?([ini, rsp], &Decibel.is_handshake_complete?/1)

    hs2 = Decibel.handshake_encrypt(rsp)
    "" = Decibel.handshake_decrypt(ini, hs2)
    assert Enum.all?([ini, rsp], &Decibel.is_handshake_complete?/1)

    data = :crypto.strong_rand_bytes(32_768)
    msg1 = Decibel.encrypt(ini, data, "The mess we're in")
    assert data != msg1
    assert data == Decibel.decrypt(rsp, msg1, "The mess we're in")

    reply = Decibel.encrypt(rsp, "Hello back")
    assert "Hello back" == Decibel.decrypt(ini, reply)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  for {pattern, cipher} <- [{"N", "AESGCM"}, {"K", "ChaChaPoly"}, {"X", "ChaChaPoly"}] do
    test "#{pattern} permits only initiator-to-responder transport even when swapped" do
      pattern = unquote(pattern)
      cipher = unquote(cipher)
      {ini, rsp} = establish_one_way_session(pattern, cipher, swap: :rsp)

      assert 0 == Decibel.get_nonce(ini, :out)
      assert 0 == Decibel.get_nonce(rsp, :in)

      error =
        assert_raise Decibel.TransportDirectionError,
                     "Outbound transport is not permitted by this one-way handshake",
                     fn -> Decibel.encrypt(rsp, "must not be allowed") end

      assert error.direction == :out
      assert 0 == Decibel.get_nonce(ini, :out)
      assert 0 == Decibel.get_nonce(rsp, :in)

      ciphertext = Decibel.encrypt(ini, "forward transport")
      assert "forward transport" == Decibel.decrypt(rsp, ciphertext)
      assert 1 == Decibel.get_nonce(ini, :out)
      assert 1 == Decibel.get_nonce(rsp, :in)

      error =
        assert_raise Decibel.TransportDirectionError,
                     "Inbound transport is not permitted by this one-way handshake",
                     fn -> Decibel.decrypt(ini, ciphertext) end

      assert error.direction == :in
      assert 1 == Decibel.get_nonce(ini, :out)
      assert 1 == Decibel.get_nonce(rsp, :in)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "one-way sessions reject cipher management for the discarded direction" do
    {ini, rsp} = establish_one_way_session("N", "ChaChaPoly", swap: :rsp)

    for operation <- [
          fn -> Decibel.get_nonce(ini, :in) end,
          fn -> Decibel.set_nonce(ini, :in, 0) end,
          fn -> Decibel.rekey(ini, :in) end
        ] do
      assert_direction_error(:in, operation)
    end

    for operation <- [
          fn -> Decibel.get_nonce(rsp, :out) end,
          fn -> Decibel.set_nonce(rsp, :out, 0) end,
          fn -> Decibel.rekey(rsp, :out) end
        ] do
      assert_direction_error(:out, operation)
    end

    assert 0 == Decibel.get_nonce(ini, :out)
    assert 0 == Decibel.get_nonce(rsp, :in)
    assert :ok == Decibel.set_nonce(ini, :out, 1)
    assert :ok == Decibel.set_nonce(rsp, :in, 1)
    assert 1 == Decibel.get_nonce(ini, :out)
    assert 1 == Decibel.get_nonce(rsp, :in)
    assert :ok == Decibel.set_nonce(ini, :out, 0)
    assert :ok == Decibel.set_nonce(rsp, :in, 0)
    assert :ok == Decibel.rekey(ini, :out)
    assert :ok == Decibel.rekey(rsp, :in)
    assert "after rekey" == Decibel.decrypt(rsp, Decibel.encrypt(ini, "after rekey"))

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Required static keys must be provided" do
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :ini) end
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :rsp) end

    {pub, priv} = :crypto.generate_key(:ecdh, :x25519)
    Decibel.close(Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub}))
    Decibel.close(Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :rsp, %{s: {pub, priv}}))
  end

  test "Required preshared keys must be provided" do
    {pub, _priv} = :crypto.generate_key(:ecdh, :x25519)
    psk0 = :crypto.strong_rand_bytes(32)
    psk2 = :crypto.strong_rand_bytes(32)
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub}) end

    assert_raise RuntimeError, fn ->
      Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub, psks: [psk0]})
    end

    Decibel.close(Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub, psks: [psk0, psk2]}))
  end

  test "Detect errors during handshake" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, :crypto.strong_rand_bytes(IO.iodata_length(hs1)))
    hs2 = Decibel.handshake_encrypt(rsp)
    assert_raise Decibel.DecryptionError, fn -> Decibel.handshake_decrypt(ini, hs2) end

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Detect errors under secure channel" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, hs1)
    hs2 = Decibel.handshake_encrypt(rsp)
    "" = Decibel.handshake_decrypt(ini, hs2)

    plaintext = :crypto.strong_rand_bytes(32_768)
    msg1 = Decibel.encrypt(ini, plaintext, "my random aad")
    assert_raise Decibel.DecryptionError, fn -> Decibel.decrypt(rsp, flip_first_bit(msg1), "my random aad") end

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Remote keys are available after handshake failure" do
    ini_s = :crypto.generate_key(:ecdh, :x25519)
    ini_e = :crypto.generate_key(:ecdh, :x25519)
    {ini_rs, _} = :crypto.generate_key(:ecdh, :x25519)
    rsp_s = :crypto.generate_key(:ecdh, :x25519)
    ini = Decibel.new("Noise_IK_25519_ChaChaPoly_BLAKE2s", :ini, %{s: ini_s, e: ini_e, rs: ini_rs})
    rsp = Decibel.new("Noise_IK_25519_ChaChaPoly_BLAKE2s", :rsp, %{s: rsp_s})

    hs1 = Decibel.handshake_encrypt(ini)

    try do
      Decibel.handshake_decrypt(rsp, hs1)
      flunk("Decryption should have failed!")
    rescue
      e in Decibel.DecryptionError ->
        {rsp_re, _} = ini_e
        assert rsp_re == e.remote_keys[:re]
    end

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Out of order messages" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, hs1)
    hs2 = Decibel.handshake_encrypt(rsp)
    "" = Decibel.handshake_decrypt(ini, hs2)

    # Generate 4 outbound messages
    assert 0 == Decibel.get_nonce(ini, :out)
    pt0 = :crypto.strong_rand_bytes(1024)
    ct0 = Decibel.encrypt(ini, pt0, <<0::unsigned-little-64>>)
    pt1 = :crypto.strong_rand_bytes(1024)
    ct1 = Decibel.encrypt(ini, pt1, <<1::unsigned-little-64>>)
    pt2 = :crypto.strong_rand_bytes(1024)
    ct2 = Decibel.encrypt(ini, pt2, <<2::unsigned-little-64>>)
    pt3 = :crypto.strong_rand_bytes(1024)
    ct3 = Decibel.encrypt(ini, pt3, <<3::unsigned-little-64>>)

    # Process them as if the first two messages had arrived out of order
    assert 0 == Decibel.get_nonce(rsp, :in)
    :ok = Decibel.set_nonce(rsp, :in, 1)
    assert pt1 == Decibel.decrypt(rsp, ct1, <<1::unsigned-little-64>>)
    :ok = Decibel.set_nonce(rsp, :in, 0)
    assert pt0 == Decibel.decrypt(rsp, ct0, <<0::unsigned-little-64>>)
    :ok = Decibel.set_nonce(rsp, :in, 2)
    assert pt2 == Decibel.decrypt(rsp, ct2, <<2::unsigned-little-64>>)
    assert pt3 == Decibel.decrypt(rsp, ct3, <<3::unsigned-little-64>>)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "transport messages are limited to 65,535 bytes" do
    for cipher <- ["ChaChaPoly", "AESGCM"] do
      {ini, rsp} = establish_session(cipher)
      plaintext = [:binary.copy(<<0>>, @max_transport_plaintext_size - 1), <<1>>]

      ciphertext = Decibel.encrypt(ini, plaintext)
      assert IO.iodata_length(ciphertext) == @max_message_size
      assert IO.iodata_to_binary(plaintext) == Decibel.decrypt(rsp, ciphertext)

      assert_raise ArgumentError, fn -> Decibel.encrypt(ini, [plaintext, <<2>>]) end

      assert Decibel.get_nonce(ini, :out) == 1
      assert "after rejection" == Decibel.decrypt(rsp, Decibel.encrypt(ini, "after rejection"))

      ciphertext = Decibel.encrypt(ini, plaintext)

      assert_raise ArgumentError, fn -> Decibel.decrypt(rsp, [ciphertext, <<0>>]) end

      assert Decibel.get_nonce(rsp, :in) == 2
      assert IO.iodata_to_binary(plaintext) == Decibel.decrypt(rsp, ciphertext)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "handshake messages are limited to 65,535 bytes" do
    max_plaintext = :binary.copy(<<0>>, @max_message_size - 32)
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    message = Decibel.handshake_encrypt(ini, max_plaintext)
    assert IO.iodata_length(message) == @max_message_size

    assert_raise ArgumentError, fn -> Decibel.handshake_decrypt(rsp, [message, <<0>>]) end

    assert max_plaintext == Decibel.handshake_decrypt(rsp, message)

    Decibel.close(ini)
    Decibel.close(rsp)

    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    assert_raise ArgumentError, fn -> Decibel.handshake_encrypt(ini, [max_plaintext, <<0>>]) end

    message = Decibel.handshake_encrypt(ini)
    assert "" == Decibel.handshake_decrypt(rsp, message)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "encrypted handshake payloads account for their authentication tag" do
    max_plaintext = :binary.copy(<<0>>, @max_message_size - 32 - 16)
    {ini, rsp} = start_nn_handshake()

    message = Decibel.handshake_encrypt(rsp, max_plaintext)
    assert IO.iodata_length(message) == @max_message_size
    assert max_plaintext == Decibel.handshake_decrypt(ini, message)

    Decibel.close(ini)
    Decibel.close(rsp)

    {ini, rsp} = start_nn_handshake()

    assert_raise ArgumentError, fn -> Decibel.handshake_encrypt(rsp, [max_plaintext, <<0>>]) end

    message = Decibel.handshake_encrypt(rsp)
    assert "" == Decibel.handshake_decrypt(ini, message)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  defp flip_first_bit(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
  defp flip_first_bit(iodata), do: flip_first_bit(IO.iodata_to_binary(iodata))

  defp establish_session(cipher) do
    protocol = "Noise_NN_25519_#{cipher}_BLAKE2s"
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

  defp establish_one_way_session(pattern, cipher, opts) do
    {ini_public, _ini_private} = ini_static = :crypto.generate_key(:ecdh, :x25519)
    {rsp_public, _rsp_private} = rsp_static = :crypto.generate_key(:ecdh, :x25519)

    {ini_keys, rsp_keys} =
      case pattern do
        "N" ->
          {%{rs: rsp_public}, %{s: rsp_static}}

        "K" ->
          {%{s: ini_static, rs: rsp_public}, %{s: rsp_static, rs: ini_public}}

        "X" ->
          {%{s: ini_static, rs: rsp_public}, %{s: rsp_static}}
      end

    protocol = "Noise_#{pattern}_25519_#{cipher}_BLAKE2s"
    ini = Decibel.new(protocol, :ini, ini_keys, opts)
    rsp = Decibel.new(protocol, :rsp, rsp_keys, opts)

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    assert Decibel.is_handshake_complete?(ini)
    assert Decibel.is_handshake_complete?(rsp)

    {ini, rsp}
  end

  defp assert_direction_error(direction, operation) do
    message =
      case direction do
        :in -> "Inbound transport is not permitted by this one-way handshake"
        :out -> "Outbound transport is not permitted by this one-way handshake"
      end

    error = assert_raise Decibel.TransportDirectionError, message, operation
    assert error.direction == direction
  end

  defp start_nn_handshake do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    {ini, rsp}
  end
end
