defmodule DecibelTest do
  use ExUnit.Case
  doctest Decibel

  @max_message_size 65_535
  @max_transport_plaintext_size @max_message_size - 16
  @invalid_psks "pre-shared keys must contain exactly one 32-byte key per psk modifier"
  @ephemeral_suites [
    %{
      curve: :x25519,
      curve_name: "25519",
      dh_len: 32,
      cipher: "ChaChaPoly",
      hash: "BLAKE2s"
    },
    %{
      curve: :x448,
      curve_name: "448",
      dh_len: 56,
      cipher: "AESGCM",
      hash: "SHA512"
    }
  ]
  @pattern_requirements [
    {"N", %{ini: [:rs], rsp: [:s]}},
    {"K", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"X", %{ini: [:s, :rs], rsp: [:s]}},
    {"NN", %{ini: [], rsp: []}},
    {"KN", %{ini: [:s], rsp: [:rs]}},
    {"NK", %{ini: [:rs], rsp: [:s]}},
    {"KK", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"NX", %{ini: [], rsp: [:s]}},
    {"KX", %{ini: [:s], rsp: [:s, :rs]}},
    {"XN", %{ini: [:s], rsp: []}},
    {"IN", %{ini: [:s], rsp: []}},
    {"XK", %{ini: [:s, :rs], rsp: [:s]}},
    {"IK", %{ini: [:s, :rs], rsp: [:s]}},
    {"XX", %{ini: [:s], rsp: [:s]}},
    {"IX", %{ini: [:s], rsp: [:s]}},
    {"NK1", %{ini: [:rs], rsp: [:s]}},
    {"NX1", %{ini: [], rsp: [:s]}},
    {"X1N", %{ini: [:s], rsp: []}},
    {"X1K", %{ini: [:s, :rs], rsp: [:s]}},
    {"XK1", %{ini: [:s, :rs], rsp: [:s]}},
    {"X1K1", %{ini: [:s, :rs], rsp: [:s]}},
    {"X1X", %{ini: [:s], rsp: [:s]}},
    {"XX1", %{ini: [:s], rsp: [:s]}},
    {"X1X1", %{ini: [:s], rsp: [:s]}},
    {"K1N", %{ini: [:s], rsp: [:rs]}},
    {"K1K", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"KK1", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"K1K1", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"K1X", %{ini: [:s], rsp: [:s, :rs]}},
    {"KX1", %{ini: [:s], rsp: [:s, :rs]}},
    {"K1X1", %{ini: [:s], rsp: [:s, :rs]}},
    {"I1N", %{ini: [:s], rsp: []}},
    {"I1K", %{ini: [:s, :rs], rsp: [:s]}},
    {"IK1", %{ini: [:s, :rs], rsp: [:s]}},
    {"I1K1", %{ini: [:s, :rs], rsp: [:s]}},
    {"I1X", %{ini: [:s], rsp: [:s]}},
    {"IX1", %{ini: [:s], rsp: [:s]}},
    {"I1X1", %{ini: [:s], rsp: [:s]}}
  ]
  @fallback_requirements [
    {"NNfallback", %{ini: [], rsp: []}},
    {"KNfallback", %{ini: [:s], rsp: [:rs]}},
    {"NXfallback", %{ini: [], rsp: [:s]}},
    {"KXfallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"XNfallback", %{ini: [:s], rsp: []}},
    {"INfallback", %{ini: [:s], rsp: [:rs]}},
    {"XXfallback", %{ini: [:s], rsp: [:s]}},
    {"IXfallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"NK1fallback", %{ini: [:rs], rsp: [:s]}},
    {"NX1fallback", %{ini: [], rsp: [:s]}},
    {"X1Nfallback", %{ini: [:s], rsp: []}},
    {"XK1fallback", %{ini: [:s, :rs], rsp: [:s]}},
    {"X1K1fallback", %{ini: [:s, :rs], rsp: [:s]}},
    {"X1Xfallback", %{ini: [:s], rsp: [:s]}},
    {"XX1fallback", %{ini: [:s], rsp: [:s]}},
    {"X1X1fallback", %{ini: [:s], rsp: [:s]}},
    {"K1Nfallback", %{ini: [:s], rsp: [:rs]}},
    {"KK1fallback", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"K1K1fallback", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"K1Xfallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"KX1fallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"K1X1fallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"I1Nfallback", %{ini: [:s], rsp: [:rs]}},
    {"IK1fallback", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"I1K1fallback", %{ini: [:s, :rs], rsp: [:s, :rs]}},
    {"I1Xfallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"IX1fallback", %{ini: [:s], rsp: [:s, :rs]}},
    {"I1X1fallback", %{ini: [:s], rsp: [:s, :rs]}}
  ]

  test "Simple NN Test" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, hs1)
    refute Enum.any?([ini, rsp], &Decibel.handshake_complete?/1)

    hs2 = Decibel.handshake_encrypt(rsp)
    "" = Decibel.handshake_decrypt(ini, hs2)
    assert Enum.all?([ini, rsp], &Decibel.handshake_complete?/1)

    data = :crypto.strong_rand_bytes(32_768)
    msg1 = Decibel.encrypt(ini, data, "The mess we're in")
    assert data != msg1
    assert data == Decibel.decrypt(rsp, msg1, "The mess we're in")

    reply = Decibel.encrypt(rsp, "Hello back")
    assert "Hello back" == Decibel.decrypt(ini, reply)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "canonical accessors and deprecated aliases return the same values" do
    ini = Decibel.new(protocol("NN"), :ini)
    rsp = Decibel.new(protocol("NN"), :rsp)

    refute Decibel.handshake_complete?(ini)
    assert Decibel.handshake_hash(ini) == nil
    assert Decibel.remote_key(ini) == nil
    refute deprecated_call(:is_handshake_complete?, [ini])
    assert deprecated_call(:get_handshake_hash, [ini]) == nil
    assert deprecated_call(:get_remote_key, [ini]) == nil

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    rsp
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(ini, &1))

    assert Decibel.handshake_complete?(ini)
    assert byte_size(Decibel.handshake_hash(ini)) == 32
    assert deprecated_call(:is_handshake_complete?, [ini])
    assert deprecated_call(:get_handshake_hash, [ini]) == Decibel.handshake_hash(ini)
    assert deprecated_call(:get_nonce, [ini, :out]) == Decibel.nonce(ini, :out)
    assert deprecated_call(:get_remote_key, [ini]) == Decibel.remote_key(ini)

    assert :ok == Decibel.close(ini)
    assert :ok == Decibel.close(rsp)
  end

  test "deprecated accessor metadata names replacements and documents removal" do
    {:docs_v1, _, _, _, _, _, docs} = Code.fetch_docs(Decibel)

    metadata =
      docs
      |> Enum.filter(&match?({{:function, _, _}, _, _, _, _}, &1))
      |> Map.new(fn {{:function, name, arity}, _, _, _, metadata} ->
        {{name, arity}, metadata}
      end)

    for {old, new} <- [
          {{:is_handshake_complete?, 1}, "handshake_complete?/1"},
          {{:get_handshake_hash, 1}, "handshake_hash/1"},
          {{:get_nonce, 2}, "nonce/2"},
          {{:get_remote_key, 1}, "remote_key/1"}
        ] do
      assert metadata[old][:deprecated] == "Use #{new} instead"

      {{:function, name, arity}, _, _, %{"en" => doc}, _} =
        Enum.find(docs, fn
          {{:function, name, arity}, _, _, _, _} -> {name, arity} == old
          _entry -> false
        end)

      assert {name, arity} == old
      assert doc =~ "Scheduled for removal in Decibel 2.0"
    end

    for current <- [
          {:handshake_complete?, 1},
          {:handshake_hash, 1},
          {:nonce, 2},
          {:remote_key, 1}
        ] do
      refute Map.has_key?(metadata[current], :deprecated)
    end
  end

  test "safe construction rejects ephemeral preloading outside fallback" do
    ephemeral = :crypto.generate_key(:ecdh, :x25519)
    {initiator_public, _initiator_private} = initiator_static = :crypto.generate_key(:ecdh, :x25519)
    {responder_public, _responder_private} = responder_static = :crypto.generate_key(:ecdh, :x25519)
    psk = :crypto.strong_rand_bytes(32)

    cases = [
      {"N", :ini, %{rs: responder_public}},
      {"K", :ini, %{s: initiator_static, rs: responder_public}},
      {"X", :ini, %{s: initiator_static, rs: responder_public}},
      {"NN", :ini, %{}},
      {"NN", :rsp, %{}},
      {"X1X1", :ini, %{s: initiator_static}},
      {"NNpsk0", :ini, %{psks: [psk]}}
    ]

    for {pattern, role, keys} <- cases do
      assert_argument_error_without_session(
        "caller-supplied :e is only permitted for a local fallback pre-message",
        fn -> Decibel.new(protocol(pattern), role, Map.put(keys, :e, ephemeral)) end
      )
    end

    assert_argument_error_without_session(
      "caller-supplied :re is only permitted for a remote fallback pre-message",
      fn ->
        Decibel.new(protocol("NN"), :ini, %{
          re: initiator_public,
          s: responder_static
        })
      end
    )
  end

  test "fallback reuses the required pre-message ephemeral for both DH functions" do
    for suite <- @ephemeral_suites do
      {prior_public, _prior_private} = prior_ephemeral = :crypto.generate_key(:ecdh, suite.curve)
      initiator_static = :crypto.generate_key(:ecdh, suite.curve)
      responder_static = :crypto.generate_key(:ecdh, suite.curve)
      protocol = suite_protocol("XXfallback", suite)

      ini =
        Decibel.new(
          protocol,
          :ini,
          %{e: prior_ephemeral, s: initiator_static},
          swap: :rsp
        )

      rsp =
        Decibel.new(
          protocol,
          :rsp,
          %{re: prior_public, s: responder_static},
          swap: :rsp
        )

      response = rsp |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      refute binary_part(response, 0, suite.dh_len) == prior_public
      assert "" == Decibel.handshake_decrypt(ini, response)

      final = Decibel.handshake_encrypt(ini)
      assert "" == Decibel.handshake_decrypt(rsp, final)
      assert Decibel.handshake_complete?(ini)
      assert Decibel.handshake_complete?(rsp)

      ciphertext = Decibel.encrypt(ini, "fallback transport")
      assert "fallback transport" == Decibel.decrypt(rsp, ciphertext)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "fallback ephemeral inputs enforce role and curve length" do
    for suite <- @ephemeral_suites do
      {public, private} = keypair = :crypto.generate_key(:ecdh, suite.curve)
      protocol = suite_protocol("XXfallback", suite)

      keypair_error =
        "fallback :e must be a keypair containing #{suite.dh_len}-byte public and private keys"

      public_error = "fallback :re must be a #{suite.dh_len}-byte public key"

      invalid_keypairs = [
        :not_a_keypair,
        public,
        {public, :not_a_private_key},
        {:not_a_public_key, private},
        {:crypto.strong_rand_bytes(suite.dh_len - 1), private},
        {:crypto.strong_rand_bytes(suite.dh_len + 1), private},
        {public, :crypto.strong_rand_bytes(suite.dh_len - 1)},
        {public, :crypto.strong_rand_bytes(suite.dh_len + 1)}
      ]

      for invalid <- invalid_keypairs do
        assert_argument_error_without_session(keypair_error, fn ->
          Decibel.new(protocol, :ini, %{e: invalid})
        end)
      end

      for invalid <- [
            :not_a_public_key,
            :crypto.strong_rand_bytes(suite.dh_len - 1),
            :crypto.strong_rand_bytes(suite.dh_len + 1)
          ] do
        assert_argument_error_without_session(public_error, fn ->
          Decibel.new(protocol, :rsp, %{re: invalid})
        end)
      end

      assert_argument_error_without_session(
        "caller-supplied :e is only permitted for a local fallback pre-message",
        fn -> Decibel.new(protocol, :rsp, %{e: keypair, re: public}) end
      )

      assert_argument_error_without_session(
        "caller-supplied :re is only permitted for a remote fallback pre-message",
        fn -> Decibel.new(protocol, :ini, %{e: keypair, re: public}) end
      )
    end
  end

  test "unsafe construction validates and ignores an unused deterministic ephemeral" do
    {responder_public, _responder_private} = responder_static = :crypto.generate_key(:ecdh, :x25519)
    unused_ephemeral = :crypto.generate_key(:ecdh, :x25519)
    protocol = protocol("N")

    ini = Decibel.new(protocol, :ini, %{rs: responder_public})
    rsp_with_override = Decibel.Unsafe.new(protocol, :rsp, %{s: responder_static, e: unused_ephemeral})
    rsp_without_override = Decibel.new(protocol, :rsp, %{s: responder_static})

    handshake = Decibel.handshake_encrypt(ini)
    assert "" == Decibel.handshake_decrypt(rsp_with_override, handshake)
    assert "" == Decibel.handshake_decrypt(rsp_without_override, handshake)

    ciphertext = Decibel.encrypt(ini, "same derived key")
    assert "same derived key" == Decibel.decrypt(rsp_with_override, ciphertext)
    assert "same derived key" == Decibel.decrypt(rsp_without_override, ciphertext)

    for ref <- [ini, rsp_with_override, rsp_without_override], do: Decibel.close(ref)

    assert_argument_error_without_session(
      "unsafe :e must be a keypair containing 32-byte public and private keys",
      fn ->
        Decibel.Unsafe.new(protocol, :rsp, %{
          s: responder_static,
          e: {:crypto.strong_rand_bytes(31), :crypto.strong_rand_bytes(32)}
        })
      end
    )
  end

  test "ordinary sessions produce distinct ephemeral keys and transport ciphertexts" do
    for suite <- @ephemeral_suites do
      {responder_public, _responder_private} =
        responder_static =
        :crypto.generate_key(:ecdh, suite.curve)

      protocol = suite_protocol("N", suite)
      ini1 = Decibel.new(protocol, :ini, %{rs: responder_public})
      ini2 = Decibel.new(protocol, :ini, %{rs: responder_public})
      rsp1 = Decibel.new(protocol, :rsp, %{s: responder_static})
      rsp2 = Decibel.new(protocol, :rsp, %{s: responder_static})

      handshake1 = ini1 |> Decibel.handshake_encrypt("same payload") |> IO.iodata_to_binary()
      handshake2 = ini2 |> Decibel.handshake_encrypt("same payload") |> IO.iodata_to_binary()

      refute binary_part(handshake1, 0, suite.dh_len) ==
               binary_part(handshake2, 0, suite.dh_len)

      assert "same payload" == Decibel.handshake_decrypt(rsp1, handshake1)
      assert "same payload" == Decibel.handshake_decrypt(rsp2, handshake2)

      ciphertext1 = Decibel.encrypt(ini1, "same transport plaintext")
      ciphertext2 = Decibel.encrypt(ini2, "same transport plaintext")
      refute IO.iodata_to_binary(ciphertext1) == IO.iodata_to_binary(ciphertext2)
      assert "same transport plaintext" == Decibel.decrypt(rsp1, ciphertext1)
      assert "same transport plaintext" == Decibel.decrypt(rsp2, ciphertext2)

      for ref <- [ini1, ini2, rsp1, rsp2], do: Decibel.close(ref)
    end
  end

  for {pattern, cipher} <- [{"N", "AESGCM"}, {"K", "ChaChaPoly"}, {"X", "ChaChaPoly"}] do
    test "#{pattern} permits only initiator-to-responder transport even when swapped" do
      pattern = unquote(pattern)
      cipher = unquote(cipher)
      {ini, rsp} = establish_one_way_session(pattern, cipher, swap: :rsp)

      assert 0 == Decibel.nonce(ini, :out)
      assert 0 == Decibel.nonce(rsp, :in)

      error =
        assert_raise Decibel.TransportDirectionError,
                     "Outbound transport is not permitted by this one-way handshake",
                     fn -> Decibel.encrypt(rsp, "must not be allowed") end

      assert error.direction == :out
      assert 0 == Decibel.nonce(ini, :out)
      assert 0 == Decibel.nonce(rsp, :in)

      ciphertext = Decibel.encrypt(ini, "forward transport")
      assert "forward transport" == Decibel.decrypt(rsp, ciphertext)
      assert 1 == Decibel.nonce(ini, :out)
      assert 1 == Decibel.nonce(rsp, :in)

      error =
        assert_raise Decibel.TransportDirectionError,
                     "Inbound transport is not permitted by this one-way handshake",
                     fn -> Decibel.decrypt(ini, ciphertext) end

      assert error.direction == :in
      assert 1 == Decibel.nonce(ini, :out)
      assert 1 == Decibel.nonce(rsp, :in)

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "one-way sessions reject cipher management for the discarded direction" do
    {ini, rsp} = establish_one_way_session("N", "ChaChaPoly", swap: :rsp)

    for operation <- [
          fn -> Decibel.nonce(ini, :in) end,
          fn -> Decibel.set_nonce(ini, :in, 0) end,
          fn -> Decibel.rekey(ini, :in) end
        ] do
      assert_direction_error(:in, operation)
    end

    for operation <- [
          fn -> Decibel.nonce(rsp, :out) end,
          fn -> Decibel.set_nonce(rsp, :out, 0) end,
          fn -> Decibel.rekey(rsp, :out) end
        ] do
      assert_direction_error(:out, operation)
    end

    assert 0 == Decibel.nonce(ini, :out)
    assert 0 == Decibel.nonce(rsp, :in)
    assert :ok == Decibel.set_nonce(ini, :out, 1)
    assert :ok == Decibel.set_nonce(rsp, :in, 1)
    assert 1 == Decibel.nonce(ini, :out)
    assert 1 == Decibel.nonce(rsp, :in)
    assert :ok == Decibel.rekey(ini, :out)
    assert :ok == Decibel.rekey(rsp, :in)
    assert "after rekey" == Decibel.decrypt(rsp, Decibel.encrypt(ini, "after rekey"))

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "all base patterns validate role-specific static requirements" do
    assert length(@pattern_requirements) == 38

    for {pattern, requirements_by_role} <- @pattern_requirements,
        {role, requirements} <- requirements_by_role do
      keys = static_key_material(role, requirements, :x25519)
      ref = Decibel.new(protocol(pattern), role, keys)
      Decibel.close(ref)

      if :s in requirements do
        assert_argument_error_without_session(
          "local static key :s is required by the selected handshake pattern",
          fn -> Decibel.new(protocol(pattern), role, Map.delete(keys, :s)) end
        )
      end

      if :rs in requirements do
        assert_argument_error_without_session(
          "remote static key :rs is required by a pre-message",
          fn -> Decibel.new(protocol(pattern), role, Map.delete(keys, :rs)) end
        )
      end
    end
  end

  test "all base patterns preserve static requirements under psk0" do
    psk = :crypto.strong_rand_bytes(32)

    for {pattern, requirements_by_role} <- @pattern_requirements,
        {role, requirements} <- requirements_by_role do
      keys = role |> static_key_material(requirements, :x25519) |> Map.put(:psks, [psk])
      ref = Decibel.new(protocol(pattern <> "psk0"), role, keys)
      Decibel.close(ref)
    end
  end

  test "all fallback patterns validate their fully modified requirements" do
    assert length(@fallback_requirements) == 28

    for {pattern, requirements_by_role} <- @fallback_requirements,
        {role, requirements} <- requirements_by_role do
      keys = fallback_key_material(role, requirements, :x25519)
      ref = Decibel.new(protocol(pattern), role, keys, swap: :rsp)
      Decibel.close(ref)

      {ephemeral_field, ephemeral_error} =
        case role do
          :ini -> {:e, "fallback :e is required by a local pre-message"}
          :rsp -> {:re, "fallback :re is required by a remote pre-message"}
        end

      assert_argument_error_without_session(ephemeral_error, fn ->
        Decibel.new(protocol(pattern), role, Map.delete(keys, ephemeral_field), swap: :rsp)
      end)

      if :s in requirements do
        assert_argument_error_without_session(
          "local static key :s is required by the selected handshake pattern",
          fn -> Decibel.new(protocol(pattern), role, Map.delete(keys, :s), swap: :rsp) end
        )
      end

      if :rs in requirements do
        assert_argument_error_without_session(
          "remote static key :rs is required by a pre-message",
          fn -> Decibel.new(protocol(pattern), role, Map.delete(keys, :rs), swap: :rsp) end
        )
      end
    end
  end

  test "PSKs compose with e and e,s fallback pre-messages" do
    psk = :crypto.strong_rand_bytes(32)

    for {pattern, requirements_by_role} <- [
          {"XXfallback+psk0", %{ini: [:s], rsp: [:s]}},
          {"INfallback+psk0", %{ini: [:s], rsp: [:rs]}}
        ],
        {role, requirements} <- requirements_by_role do
      keys = role |> fallback_key_material(requirements, :x25519) |> Map.put(:psks, [psk])
      ref = Decibel.new(protocol(pattern), role, keys, swap: :rsp)
      Decibel.close(ref)
    end
  end

  test "static keypairs enforce shape and exact curve lengths" do
    for suite <- @ephemeral_suites do
      {public, private} = keypair = :crypto.generate_key(:ecdh, suite.curve)

      error =
        "local static key :s must be a keypair containing #{suite.dh_len}-byte public and private keys"

      invalid_keypairs = [
        :not_a_keypair,
        public,
        {public},
        {public, private, :extra},
        {public, :not_a_private_key},
        {:not_a_public_key, private},
        {:crypto.strong_rand_bytes(suite.dh_len - 1), private},
        {:crypto.strong_rand_bytes(suite.dh_len + 1), private},
        {public, :crypto.strong_rand_bytes(suite.dh_len - 1)},
        {public, :crypto.strong_rand_bytes(suite.dh_len + 1)}
      ]

      for invalid <- invalid_keypairs do
        assert_argument_error_without_session(error, fn ->
          Decibel.new(suite_protocol("XX", suite), :ini, %{s: invalid})
        end)
      end

      ref = Decibel.new(suite_protocol("XX", suite), :ini, %{s: keypair})
      Decibel.close(ref)
    end
  end

  test "remote static keys enforce pre-message compatibility and curve length" do
    for suite <- @ephemeral_suites do
      {public, _private} = :crypto.generate_key(:ecdh, suite.curve)
      error = "remote static key :rs must be a #{suite.dh_len}-byte public key"

      for invalid <- [
            :not_a_public_key,
            :crypto.strong_rand_bytes(suite.dh_len - 1),
            :crypto.strong_rand_bytes(suite.dh_len + 1)
          ] do
        assert_argument_error_without_session(error, fn ->
          Decibel.new(suite_protocol("N", suite), :ini, %{rs: invalid})
        end)
      end

      ref = Decibel.new(suite_protocol("N", suite), :ini, %{rs: public})
      Decibel.close(ref)

      assert_argument_error_without_session(
        "caller-supplied :rs is only permitted for a remote static pre-message",
        fn -> Decibel.new(suite_protocol("NN", suite), :ini, %{rs: public}) end
      )
    end
  end

  test "static validation depends only on the selected DH function" do
    for suite <- @ephemeral_suites,
        cipher <- ["ChaChaPoly", "AESGCM"],
        hash <- ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"] do
      keys = static_key_material(:ini, [:s, :rs], suite.curve)
      protocol = "Noise_K_#{suite.curve_name}_#{cipher}_#{hash}"
      ref = Decibel.new(protocol, :ini, keys)
      Decibel.close(ref)
    end
  end

  test "prologue must be valid iodata" do
    for prologue <- [<<>>, [], "binary", [0, [1, <<2, 3>>]], [<<1>> | <<2, 3>>]] do
      ref = Decibel.new(protocol("NN"), :ini, %{prologue: prologue})
      Decibel.close(ref)
    end

    for invalid <- [:atom, {:tuple}, 1.5, [256], [<<1>> | :not_a_binary_tail]] do
      assert_argument_error_without_session("prologue must be valid iodata", fn ->
        Decibel.new(protocol("NN"), :ini, %{prologue: invalid})
      end)
    end
  end

  test "constructor normalizes top-level configuration argument errors" do
    assert_argument_error_without_session("protocol name must be a string", fn ->
      Decibel.new(:not_a_protocol_name, :ini)
    end)

    assert_argument_error_without_session("role must be :ini or :rsp", fn ->
      Decibel.new(protocol("NN"), :sender)
    end)

    assert_argument_error_without_session("key material must be a map", fn ->
      Decibel.new(protocol("NN"), :ini, [])
    end)
  end

  test "construction options validate shape, uniqueness, and values" do
    for opts <- [[], [swap: :ini], [swap: :rsp]] do
      ref = Decibel.new(protocol("NN"), :ini, %{}, opts)
      Decibel.close(ref)
    end

    assert_argument_error_without_session("options must be a keyword list", fn ->
      Decibel.new(protocol("NN"), :ini, %{}, :not_options)
    end)

    assert_argument_error_without_session("unsupported construction option: :bogus", fn ->
      Decibel.new(protocol("NN"), :ini, %{}, bogus: true)
    end)

    assert_argument_error_without_session(
      "construction option :swap may only be specified once",
      fn -> Decibel.new(protocol("NN"), :ini, %{}, swap: :ini, swap: :rsp) end
    )

    for invalid <- [:invalid, nil, "ini"] do
      assert_argument_error_without_session(
        "construction option :swap must be :ini or :rsp",
        fn -> Decibel.new(protocol("NN"), :ini, %{}, swap: invalid) end
      )
    end

    assert_argument_error_without_session("unsupported construction option: :registry", fn ->
      Decibel.new(protocol("NN"), :ini, %{}, registry: Decibel.Registry)
    end)

    assert_argument_error_without_session("unsupported construction option: :registry", fn ->
      Decibel.Unsafe.new(protocol("NN"), :ini, %{}, registry: Decibel.Registry)
    end)
  end

  test "constructor preserves protocol, ephemeral, and PSK error precedence" do
    invalid_protocol = "Noise_NNpsk01_25519_ChaChaPoly_BLAKE2s"

    assert_argument_error_without_session(
      "invalid Noise protocol name: unsupported modifier \"psk01\"",
      fn -> Decibel.new(invalid_protocol, :ini, %{e: :invalid, psks: []}, bogus: true) end
    )

    ephemeral = :crypto.generate_key(:ecdh, :x25519)

    assert_argument_error_without_session(
      "caller-supplied :e is only permitted for a local fallback pre-message",
      fn -> Decibel.new(protocol("NNpsk0"), :ini, %{e: ephemeral}) end
    )

    assert_argument_error_without_session(@invalid_psks, fn ->
      Decibel.new(protocol("XXpsk0"), :ini)
    end)
  end

  test "Required preshared keys must be provided" do
    {pub, _priv} = :crypto.generate_key(:ecdh, :x25519)
    psk0 = :crypto.strong_rand_bytes(32)
    psk2 = :crypto.strong_rand_bytes(32)
    protocol = "Noise_NKpsk0+psk2_25519_ChaChaPoly_BLAKE2s"

    assert_argument_error_without_session(@invalid_psks, fn -> Decibel.new(protocol, :ini, %{rs: pub}) end)

    assert_argument_error_without_session(@invalid_psks, fn ->
      Decibel.new(protocol, :ini, %{rs: pub, psks: [psk0]})
    end)

    for invalid <- [
          [psk0, psk2, :crypto.strong_rand_bytes(32)],
          [:crypto.strong_rand_bytes(31), psk2],
          [:crypto.strong_rand_bytes(33), psk2],
          [psk0, :invalid],
          :not_a_list
        ] do
      assert_argument_error_without_session(@invalid_psks, fn ->
        Decibel.new(protocol, :ini, %{rs: pub, psks: invalid})
      end)
    end

    Decibel.close(Decibel.new(protocol, :ini, %{rs: pub, psks: [psk0, psk2]}))

    assert_argument_error_without_session(@invalid_psks, fn ->
      Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini, %{psks: [psk0]})
    end)
  end

  test "PSK indices are bounded by each handshake pattern" do
    {responder_static, _private} = :crypto.generate_key(:ecdh, :x25519)
    initiator_static = :crypto.generate_key(:ecdh, :x25519)
    fallback_static = :crypto.generate_key(:ecdh, :x25519)
    psk = :crypto.strong_rand_bytes(32)

    for pattern <- ["Npsk0", "Npsk1"] do
      ref = Decibel.new(protocol(pattern), :ini, %{rs: responder_static, psks: [psk]})
      Decibel.close(ref)
    end

    for pattern <- ["NNpsk0", "NNpsk2"] do
      ref = Decibel.new(protocol(pattern), :ini, %{psks: [psk]})
      Decibel.close(ref)
    end

    for pattern <- ["X1Npsk0", "X1Npsk4"] do
      ref = Decibel.new(protocol(pattern), :ini, %{s: initiator_static, psks: [psk]})
      Decibel.close(ref)
    end

    for pattern <- ["XXfallback+psk0", "XXfallback+psk2"] do
      ref = Decibel.new(protocol(pattern), :rsp, %{re: responder_static, s: fallback_static, psks: [psk]})
      Decibel.close(ref)
    end

    for {pattern, index} <- [{"Npsk2", 2}, {"NNpsk3", 3}, {"X1Npsk5", 5}, {"XXfallback+psk3", 3}] do
      assert_raise ArgumentError,
                   "invalid Noise protocol name: psk#{index} does not reference a handshake message",
                   fn -> Decibel.new(protocol(pattern), :ini, %{psks: [psk]}) end
    end
  end

  test "fallback validates the current first message and composes sequentially" do
    remote_ephemeral = :crypto.strong_rand_bytes(32)
    remote_static = :crypto.strong_rand_bytes(32)
    local_static = :crypto.generate_key(:ecdh, :x25519)
    psk = :crypto.strong_rand_bytes(32)

    ref =
      Decibel.new(protocol("IXfallback"), :rsp, %{
        re: remote_ephemeral,
        rs: remote_static,
        s: local_static
      })

    Decibel.close(ref)

    ref =
      Decibel.new(protocol("XXpsk2+fallback"), :rsp, %{
        re: remote_ephemeral,
        s: local_static,
        psks: [psk]
      })

    Decibel.close(ref)

    for pattern <- ["NKfallback", "XXpsk0+fallback", "XXpsk1+fallback"] do
      assert_raise ArgumentError,
                   "invalid Noise protocol name: fallback is not applicable to this handshake pattern",
                   fn -> Decibel.new(protocol(pattern), :ini, %{psks: [psk]}) end
    end
  end

  test "PSK tokens consume exactly one key in modifier order" do
    psks = [:crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(32)]
    protocol = protocol("NNpsk0+psk2")
    ini = Decibel.new(protocol, :ini, %{psks: psks})
    rsp = Decibel.new(protocol, :rsp, %{psks: psks})

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    rsp
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(ini, &1))

    assert Decibel.handshake_complete?(ini)
    assert Decibel.handshake_complete?(rsp)
    Decibel.close(ini)
    Decibel.close(rsp)
  end

  test "unknown patterns from the built-in registry raise a stable error" do
    assert_raise ArgumentError,
                 "invalid Noise protocol name: unsupported handshake pattern \"ZZ\"",
                 fn ->
                   Decibel.new(protocol("ZZ"), :ini)
                 end
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
    ini = Decibel.Unsafe.new("Noise_IK_25519_ChaChaPoly_BLAKE2s", :ini, %{s: ini_s, e: ini_e, rs: ini_rs})
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

  test "low-level inbound nonce selection supports out-of-order messages" do
    ini = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :ini)
    rsp = Decibel.new("Noise_NN_25519_ChaChaPoly_BLAKE2s", :rsp)

    hs1 = Decibel.handshake_encrypt(ini)
    "" = Decibel.handshake_decrypt(rsp, hs1)
    hs2 = Decibel.handshake_encrypt(rsp)
    "" = Decibel.handshake_decrypt(ini, hs2)

    # Generate 4 outbound messages
    assert 0 == Decibel.nonce(ini, :out)
    pt0 = :crypto.strong_rand_bytes(1024)
    ct0 = Decibel.encrypt(ini, pt0, <<0::unsigned-little-64>>)
    pt1 = :crypto.strong_rand_bytes(1024)
    ct1 = Decibel.encrypt(ini, pt1, <<1::unsigned-little-64>>)
    pt2 = :crypto.strong_rand_bytes(1024)
    ct2 = Decibel.encrypt(ini, pt2, <<2::unsigned-little-64>>)
    pt3 = :crypto.strong_rand_bytes(1024)
    ct3 = Decibel.encrypt(ini, pt3, <<3::unsigned-little-64>>)

    # This exercises the low-level primitive only. Applications must separately
    # track successfully authenticated nonces and reject replays.
    assert 0 == Decibel.nonce(rsp, :in)
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
      assert_raise ArgumentError, fn -> Decibel.encrypt_with_nonce(ini, [plaintext, <<2>>]) end

      assert Decibel.nonce(ini, :out) == 1
      assert "after rejection" == Decibel.decrypt(rsp, Decibel.encrypt(ini, "after rejection"))

      ciphertext = Decibel.encrypt(ini, plaintext)

      assert_raise ArgumentError, fn -> Decibel.decrypt(rsp, [ciphertext, <<0>>]) end
      assert_raise ArgumentError, fn -> Decibel.decrypt(rsp, [ciphertext, <<0>>], [], nonce: 2) end

      assert Decibel.nonce(rsp, :in) == 2
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

  # Dynamic invocation verifies deprecated forwarders without compiler warnings.
  # credo:disable-for-next-line Credo.Check.Refactor.Apply
  defp deprecated_call(name, arguments), do: apply(Decibel, name, arguments)

  defp protocol(pattern), do: "Noise_#{pattern}_25519_ChaChaPoly_BLAKE2s"

  defp suite_protocol(pattern, suite) do
    "Noise_#{pattern}_#{suite.curve_name}_#{suite.cipher}_#{suite.hash}"
  end

  defp assert_argument_error_without_session(message, operation) do
    sessions = decibel_sessions()
    assert_raise ArgumentError, message, operation
    assert decibel_sessions() == sessions
  end

  defp decibel_sessions do
    Process.get()
    |> Enum.filter(fn
      {_key, %Decibel.Handshake{}} -> true
      {_key, %Decibel.ChannelPair{}} -> true
      {_key, _value} -> false
    end)
    |> Map.new()
  end

  defp static_key_material(role, requirements, curve) do
    {initiator_public, _initiator_private} = initiator_static = :crypto.generate_key(:ecdh, curve)
    {responder_public, _responder_private} = responder_static = :crypto.generate_key(:ecdh, curve)

    Enum.reduce(requirements, %{}, fn
      :s, keys ->
        Map.put(keys, :s, if(role == :ini, do: initiator_static, else: responder_static))

      :rs, keys ->
        Map.put(keys, :rs, if(role == :ini, do: responder_public, else: initiator_public))
    end)
  end

  defp fallback_key_material(role, requirements, curve) do
    {prior_public, _prior_private} = prior_ephemeral = :crypto.generate_key(:ecdh, curve)
    keys = static_key_material(role, requirements, curve)

    case role do
      :ini -> Map.put(keys, :e, prior_ephemeral)
      :rsp -> Map.put(keys, :re, prior_public)
    end
  end

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

    assert Decibel.handshake_complete?(ini)
    assert Decibel.handshake_complete?(rsp)

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
