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

    assert Utility.parse_protocol_name("Noise_XXfallback+psk1_448_ChaChaPoly_SHA512") ==
             {{"XX", [:fallback, {:psk, 1}]}, :x448, :chacha20_poly1305, :sha512}
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

  test "rejects malformed protocol names with stable errors" do
    cases = [
      {"Noise_NN_25519_ChaChaPoly", "invalid Noise protocol name: expected Noise_<handshake>_<dh>_<cipher>_<hash>"},
      {"Noise_NN__ChaChaPoly_BLAKE2s", "invalid Noise protocol name: expected Noise_<handshake>_<dh>_<cipher>_<hash>"},
      {"Noise_NN+psk0_25519_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: invalid handshake pattern section"},
      {"Noise_NNpsk0+_25519_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: invalid handshake pattern section"},
      {"Noise_NNpsk01_25519_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: unsupported modifier \"psk01\""},
      {"Noise_NNticket_25519_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: unsupported modifier \"ticket\""},
      {"Noise_NNpsk0+psk0_25519_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: duplicate modifier \"psk0\""},
      {"Noise_NNfallback+fallback_25519_ChaChaPoly_BLAKE2s",
       "invalid Noise protocol name: duplicate modifier \"fallback\""},
      {"Noise_NNpsk2+psk1_25519_ChaChaPoly_BLAKE2s",
       "invalid Noise protocol name: psk modifiers must be listed in canonical order"},
      {"Noise_NN_12345_ChaChaPoly_BLAKE2s", "invalid Noise protocol name: unsupported DH function \"12345\""},
      {"Noise_NN_25519_ROT13_BLAKE2s", "invalid Noise protocol name: unsupported cipher function \"ROT13\""},
      {"Noise_NN_25519_ChaChaPoly_MD5", "invalid Noise protocol name: unsupported hash function \"MD5\""}
    ]

    for {protocol_name, message} <- cases do
      assert_raise ArgumentError, message, fn -> Utility.parse_protocol_name(protocol_name) end
    end
  end

  test "limits protocol names to 255 bytes" do
    prefix = "Noise_NN_25519_ChaChaPoly_"
    at_limit = prefix <> String.duplicate("A", 255 - byte_size(prefix))
    over_limit = at_limit <> "A"

    error = assert_raise ArgumentError, fn -> Utility.parse_protocol_name(at_limit) end
    refute error.message =~ "must not exceed"

    assert_raise ArgumentError, "invalid Noise protocol name: must not exceed 255 bytes", fn ->
      Utility.parse_protocol_name(over_limit)
    end
  end

  test "modify_handshake applies PSKs at valid boundaries" do
    nn = {[], [ini: [:e], rsp: [:e, :ee]]}

    assert Utility.modify_handshake(nn, [{:psk, 0}, {:psk, 2}]) ==
             {[], [ini: [:psk, :e], rsp: [:e, :ee, :psk]]}

    assert_raise ArgumentError,
                 "invalid Noise protocol name: psk3 does not reference a handshake message",
                 fn -> Utility.modify_handshake(nn, [{:psk, 3}]) end
  end

  test "modify_handshake validates and applies fallback sequentially" do
    for tokens <- [[:e], [:s], [:e, :s]] do
      assert Utility.modify_handshake({[], [ini: tokens, rsp: [:e]]}, [:fallback]) ==
               {[ini: tokens], [rsp: [:e]]}
    end

    invalid_patterns = [
      {[], []},
      {[], [rsp: [:e]]},
      {[], [ini: []]},
      {[], [ini: [:e, :es]]}
    ]

    for pattern <- invalid_patterns do
      assert_raise ArgumentError,
                   "invalid Noise protocol name: fallback is not applicable to this handshake pattern",
                   fn -> Utility.modify_handshake(pattern, [:fallback]) end
    end

    xx = {[], [ini: [:e], rsp: [:e, :ee, :s, :es], ini: [:s, :se]]}

    assert Utility.modify_handshake(xx, [:fallback, {:psk, 2}]) ==
             {[ini: [:e]], [rsp: [:e, :ee, :s, :es], ini: [:s, :se, :psk]]}

    assert Utility.modify_handshake(xx, [{:psk, 2}, :fallback]) ==
             {[ini: [:e]], [rsp: [:e, :ee, :s, :es, :psk], ini: [:s, :se]]}

    for modifier <- [{:psk, 0}, {:psk, 1}] do
      assert_raise ArgumentError,
                   "invalid Noise protocol name: fallback is not applicable to this handshake pattern",
                   fn -> Utility.modify_handshake(xx, [modifier, :fallback]) end
    end
  end

  test "has_preshared_keys requires one 32-byte key per token" do
    assert Utility.has_preshared_keys([], [])
    assert Utility.has_preshared_keys([{:ini, [:psk]}], [<<0::256>>])
    assert Utility.has_preshared_keys([{:ini, [:e, :psk]}], [<<0::256>>])
    assert Utility.has_preshared_keys([{:ini, [:psk]}, {:rsp, [:e, :psk]}], [<<0::256>>, <<1::256>>])
    assert Utility.has_preshared_keys([{:ini, [:e, :s]}], [])
    refute Utility.has_preshared_keys([{:ini, [:psk]}], [])
    refute Utility.has_preshared_keys([], [<<0::256>>])
    refute Utility.has_preshared_keys([{:ini, [:psk]}], [<<0::248>>])
    refute Utility.has_preshared_keys([{:ini, [:psk]}], :not_a_list)
    refute Utility.has_preshared_keys([{:ini, [:e]}, {:rsp, [:psk, :e]}], [])
  end
end
