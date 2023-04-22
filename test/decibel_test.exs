defmodule DecibelTest do
  use ExUnit.Case
  doctest Decibel

  test "Simple NN Test" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    ""  = Decibel.handshake_decrypt(rsp, hs1)
    refute Enum.any?([ini, rsp], &Decibel.is_handshake_complete?/1)

    hs2 = Decibel.handshake_encrypt(rsp)
    ""  = Decibel.handshake_decrypt(ini, hs2)
    assert Enum.all?([ini, rsp], &Decibel.is_handshake_complete?/1)

    data = :crypto.strong_rand_bytes(32768)
    msg1 = Decibel.encrypt(ini, data, "The mess we're in")
    assert data != msg1
    assert data == Decibel.decrypt(rsp, msg1, "The mess we're in")

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Required static keys must be provided" do
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :ini) end
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :rsp) end

    {pub, priv} = :crypto.generate_key(:ecdh, :x25519)
    Decibel.close(Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub}))
    Decibel.close(Decibel.new("Noise_NK_25519_ChaChaPoly_BLAKE2s", :rsp, %{s:  {pub, priv}}))
  end

  test "Required preshared keys must be provided" do
    {pub, _priv} = :crypto.generate_key(:ecdh, :x25519)
    psk0 = :crypto.strong_rand_bytes(32)
    psk2 = :crypto.strong_rand_bytes(32)
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub}) end
    assert_raise RuntimeError, fn -> Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub, psks: [psk0]}) end
    Decibel.close(Decibel.new("Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: pub, psks: [psk0, psk2]}))
  end

  test "Detect errors during handshake" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    ""  = Decibel.handshake_decrypt(rsp, :crypto.strong_rand_bytes(IO.iodata_length(hs1)))
    hs2 = Decibel.handshake_encrypt(rsp)
    assert_raise RuntimeError, fn -> Decibel.handshake_decrypt(ini, hs2) end

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Detect errors under secure channel" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    ""  = Decibel.handshake_decrypt(rsp, hs1)
    hs2 = Decibel.handshake_encrypt(rsp)
    ""  = Decibel.handshake_decrypt(ini, hs2)

    plaintext = :crypto.strong_rand_bytes(32768)
    msg1 = Decibel.encrypt(ini, plaintext, "my random aad")
    assert_raise RuntimeError, fn-> Decibel.decrypt(rsp, flip_first_two_bytes(msg1), "my random aad") end

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "Correct role" do
  end

  defp flip_first_two_bytes(<<fst, snd, rest::binary>>), do: <<snd, fst, rest::binary>>
  defp flip_first_two_bytes(iodata), do: flip_first_two_bytes(IO.iodata_to_binary(iodata))
end
