defmodule UtilityTest do
  use ExUnit.Case

  alias Decibel.Utility

  test "parse_handshake" do
    assert Utility.parse_handshake("XX") == {"XX", []}
    assert Utility.parse_handshake("XXfallback") == {"XX", [:fallback]}
    assert Utility.parse_handshake("XXfallback+psk0") == {"XX", [:fallback, {:psk, 0}]}
    assert Utility.parse_handshake("XXpsk0") == {"XX", [{:psk, 0}]}
    assert Utility.parse_handshake("XXfallback+psk0+psk1") == {"XX", [:fallback, {:psk, 0}, {:psk, 1}]}
    assert Utility.parse_handshake("KKpsk0+psk2") == {"KK", [{:psk, 0}, {:psk, 2}]}
  end

  test "split_handshake" do
    sep = {:..., []}
    assert Utility.split_handshake([1, 2, 3]) == {[], [1, 2, 3]}
    assert Utility.split_handshake([sep, 1, 2, 3]) == {[], [1, 2, 3]}
    assert Utility.split_handshake([1, sep, 2, 3]) == {[1], [2, 3]}
    assert Utility.split_handshake([1, 2, sep, 3]) == {[1, 2], [3]}
    assert Utility.split_handshake([1, 2, 3, sep]) == {[1, 2, 3], []}
  end

  test "parse_protocol_name" do
    assert Utility.parse_protocol_name("Noise_XX_25519_AESGCM_SHA256") == {{"XX", []}, :x25519, :aes_256_gcm, :sha256}

    assert Utility.parse_protocol_name("Noise_KK_448_ChaChaPoly_SHA512") ==
             {{"KK", []}, :x448, :chacha20_poly1305, :sha512}

    assert Utility.parse_protocol_name("Noise_KKfallback+psk1_448_ChaChaPoly_SHA512") ==
             {{"KK", [:fallback, {:psk, 1}]}, :x448, :chacha20_poly1305, :sha512}
  end

  for curve <- ["25519", "448"] do
    for cipher <- ["ChaChaPoly", "AESGCM"] do
      for hash <- ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"] do
        test "parse Noise_KK_#{curve}_#{cipher}_#{hash}" do
          assert match?(
                   {{"KK", _}, _, _, _},
                   Utility.parse_protocol_name("Noise_KK_#{unquote(curve)}_#{unquote(cipher)}_#{unquote(hash)}")
                 )
        end
      end
    end
  end

  test "has_preshared_key" do
    assert Utility.has_preshared_keys([], [])
    assert Utility.has_preshared_keys([{:ini, [:psk]}], [<<0::256>>])
    assert Utility.has_preshared_keys([{:ini, [:e, :psk]}], [<<0::256>>])
    assert Utility.has_preshared_keys([{:ini, [:e, :s]}], [])
    refute Utility.has_preshared_keys([{:ini, [:psk]}], [])
    refute Utility.has_preshared_keys([{:ini, [:e]}, {:rsp, [:psk, :e]}], [])
  end
end
