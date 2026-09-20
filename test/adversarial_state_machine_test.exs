# The complete finite matrix runs once by default. Set
# DECIBEL_STATE_MACHINE_RUNS to a positive integer for more generated variants,
# and DECIBEL_STATE_MACHINE_SEED to reproduce or select the generated data.
defmodule Decibel.AdversarialStateMachineTest do
  use ExUnit.Case

  alias Decibel.{DecryptionError, NonceError, SessionError, TransportDirectionError}

  @default_seed 18_034
  @seed System.get_env("DECIBEL_STATE_MACHINE_SEED", Integer.to_string(@default_seed))
        |> String.to_integer()
  @runs System.get_env("DECIBEL_STATE_MACHINE_RUNS", "1") |> String.to_integer()

  if @seed < 0, do: raise("DECIBEL_STATE_MACHINE_SEED must be a non-negative integer")
  if @runs < 1, do: raise("DECIBEL_STATE_MACHINE_RUNS must be a positive integer")

  @patterns [
    %{name: "N", turns: [:ini], authenticated: [0], mode: :one_way},
    %{name: "NN", turns: [:ini, :rsp], authenticated: [1], mode: :interactive},
    %{name: "XX", turns: [:ini, :rsp, :ini], authenticated: [1, 2], mode: :interactive},
    %{name: "X1X1", turns: [:ini, :rsp, :ini, :rsp], authenticated: [1, 2, 3], mode: :interactive},
    %{name: "NNpsk0", turns: [:ini, :rsp], authenticated: [0, 1], mode: :interactive},
    %{name: "XXfallback", turns: [:rsp, :ini], authenticated: [0, 1], mode: :interactive}
  ]

  @suites (for {curve, curve_name, dh_len} <- [
                 {:x25519, "25519", 32},
                 {:x448, "448", 56}
               ],
               cipher <- ["ChaChaPoly", "AESGCM"],
               hash <- ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"] do
             %{
               curve: curve,
               curve_name: curve_name,
               dh_len: dh_len,
               cipher: cipher,
               hash: hash,
               hash_len: if(hash in ["SHA256", "BLAKE2s"], do: 32, else: 64)
             }
           end)

  @final_usable_nonce 2 ** 64 - 2
  @before_final_nonce @final_usable_nonce - 1
  @reserved_nonce @final_usable_nonce + 1

  setup_all do
    IO.puts("Decibel adversarial state-machine seed=#{@seed} runs=#{@runs}")
    {:ok, seed: @seed, runs: @runs}
  end

  test "public state machine rejects hostile transitions and preserves failed input state", %{
    seed: seed,
    runs: runs
  } do
    initial_state = :rand.seed_s(:exsss, {seed + 1, seed + 2, seed + 3})

    final_state =
      Enum.reduce(1..runs, initial_state, fn run, random_state ->
        Enum.reduce(@patterns, random_state, fn pattern, random_state ->
          Enum.reduce(@suites, random_state, fn suite, random_state ->
            {data, random_state} = generated_data(random_state, run)
            exercise_lifecycle(pattern, suite, data)
            random_state
          end)
        end)
      end)

    assert is_tuple(final_state)
  end

  test "malformed protocol names fail stably without creating sessions" do
    prefix = "Noise_NN_25519_ChaChaPoly_"
    at_limit = prefix <> String.duplicate("A", 255 - byte_size(prefix))

    malformed = [
      "",
      "Noise",
      "Noise_NN_25519_ChaChaPoly",
      "Noise_NN__ChaChaPoly_BLAKE2s",
      "Noise_NN_25519_ChaChaPoly_BLAKE2s_extra",
      "Noise_ZZ_25519_ChaChaPoly_BLAKE2s",
      "Noise_NN_12345_ChaChaPoly_BLAKE2s",
      "Noise_NN_25519_ROT13_BLAKE2s",
      "Noise_NN_25519_ChaChaPoly_MD5",
      "Noise_NN+psk0_25519_ChaChaPoly_BLAKE2s",
      "Noise_NNpsk0+_25519_ChaChaPoly_BLAKE2s",
      "Noise_NNpsk01_25519_ChaChaPoly_BLAKE2s",
      "Noise_NNpsk0+psk0_25519_ChaChaPoly_BLAKE2s",
      "Noise_NNpsk2+psk1_25519_ChaChaPoly_BLAKE2s",
      "Noise_NNpsk3_25519_ChaChaPoly_BLAKE2s",
      "Noise_NN_25519_ChaChaPoly_BLAKE2s\0",
      "Noise_NN_25519_ChaChaPoly_" <> <<255>>,
      at_limit,
      at_limit <> "A"
    ]

    for protocol <- malformed do
      before = session_entries()
      error = assert_raise ArgumentError, fn -> Decibel.new(protocol, :ini) end
      assert error.message =~ "invalid Noise protocol name:"
      assert session_entries() == before
    end
  end

  test "invalid public keys never leak crypto exceptions and leave the handshake retryable" do
    for suite <- @suites do
      {responder_public, _private} = responder_static = :crypto.generate_key(:ecdh, suite.curve)
      protocol = protocol("N", suite)
      initiator = Decibel.new(protocol, :ini, %{rs: responder_public})
      responder = Decibel.new(protocol, :rsp, %{s: responder_static})
      valid = initiator |> Decibel.handshake_encrypt() |> IO.iodata_to_binary()
      invalid_key = :binary.copy(<<0>>, suite.dh_len)

      error =
        assert_decryption_error(:invalid_public_key, fn ->
          Decibel.handshake_decrypt(responder, fragment(invalid_key, 4))
        end)

      assert error.remote_keys == [re: invalid_key, rs: nil]
      refute Decibel.handshake_complete?(responder)
      assert "" == Decibel.handshake_decrypt(responder, fragment(valid, 3))
      assert Decibel.handshake_complete?(responder)

      close_all([initiator, responder])
    end
  end

  test "malformed transport inputs preserve nonce across every primitive combination" do
    for {suite, suite_index} <- Enum.with_index(@suites) do
      {initiator, responder} = establish_nn(suite, fragment("transport prologue", suite_index))
      aad = fragment("transport aad", suite_index + 1)
      ciphertext = initiator |> Decibel.encrypt(fragment("transport payload", suite_index + 2), aad) |> binary()

      for length <- 0..15 do
        assert_decryption_error(:truncated, fn ->
          Decibel.decrypt(responder, fragment(:binary.copy(<<0>>, length), length), aad)
        end)

        assert Decibel.nonce(responder, :in) == 0
      end

      for operation <- [
            fn -> Decibel.decrypt(responder, fragment(flip_last_byte(ciphertext), suite_index), aad) end,
            fn -> Decibel.decrypt(responder, fragment(ciphertext, suite_index), ["wrong ", aad]) end,
            fn -> Decibel.decrypt(responder, fragment(flip_last_byte(ciphertext), suite_index + 1), aad) end
          ] do
        assert_decryption_error(:authentication_failed, operation)
        assert Decibel.nonce(responder, :in) == 0
      end

      assert "transport payload" == Decibel.decrypt(responder, fragment(ciphertext, suite_index + 3), aad)
      assert Decibel.nonce(responder, :in) == 1

      close_all([initiator, responder])
    end
  end

  test "nonce boundaries are stable across every primitive combination" do
    for suite <- @suites do
      {sender, recipient} = establish_nn(suite, [])

      assert :ok == Decibel.set_nonce(sender, :out, 5)
      assert :ok == Decibel.set_nonce(recipient, :in, 5)

      rewind =
        assert_raise NonceError, "Outbound nonce cannot move backwards from 5 to 4", fn ->
          Decibel.set_nonce(sender, :out, 4)
        end

      assert rewind.reason == :rewind
      assert rewind.nonce == 4
      assert rewind.current_nonce == 5
      assert Decibel.nonce(sender, :out) == 5

      for {session, direction} <- [{sender, :out}, {recipient, :in}],
          invalid <- [-1, @reserved_nonce, @reserved_nonce + 1, :not_a_nonce] do
        previous = Decibel.nonce(session, direction)
        error = assert_raise NonceError, fn -> Decibel.set_nonce(session, direction, invalid) end
        assert error.reason == :out_of_range
        assert error.nonce == invalid
        assert Decibel.nonce(session, direction) == previous
      end

      assert :ok == Decibel.set_nonce(sender, :out, @before_final_nonce)
      assert :ok == Decibel.set_nonce(recipient, :in, @before_final_nonce)

      before_final = Decibel.encrypt(sender, "before final")
      assert "before final" == Decibel.decrypt(recipient, before_final)
      assert Decibel.nonce(sender, :out) == @final_usable_nonce
      assert Decibel.nonce(recipient, :in) == @final_usable_nonce

      final = Decibel.encrypt(sender, "final")
      assert "final" == Decibel.decrypt(recipient, final)
      assert Decibel.nonce(sender, :out) == @reserved_nonce
      assert Decibel.nonce(recipient, :in) == @reserved_nonce

      for operation <- [
            fn -> Decibel.encrypt(sender, "exhausted") end,
            fn -> Decibel.decrypt(recipient, final) end
          ] do
        error = assert_raise NonceError, "Cipher nonce is exhausted", operation
        assert error.reason == :exhausted
        assert error.nonce == @reserved_nonce
      end

      assert Decibel.nonce(sender, :out) == @reserved_nonce
      assert Decibel.nonce(recipient, :in) == @reserved_nonce

      close_all([sender, recipient])
    end
  end

  test "closing during every handshake class is terminal" do
    for {pattern, index} <- Enum.with_index(@patterns) do
      suite = Enum.at(@suites, rem(index, length(@suites)))
      {initiator, responder} = new_pair(pattern, suite, fragment("close prologue", index))

      assert :ok == Decibel.close(initiator)
      assert_closed(initiator)
      assert :ok == Decibel.close(responder)
      assert_closed(responder)
    end
  end

  defp exercise_lifecycle(pattern, suite, data) do
    {initiator, responder} = new_pair(pattern, suite, fragment(data.prologue, data.variant))
    sessions = %{ini: initiator, rsp: responder}

    pattern.turns
    |> Enum.with_index()
    |> Enum.each(fn {writer_role, message_index} ->
      reader_role = opposite(writer_role)
      writer = sessions[writer_role]
      reader = sessions[reader_role]
      remaining_before = Enum.drop(pattern.turns, message_index)
      remaining_after = tl(remaining_before)

      assert_phase(writer, phase_for(writer_role, remaining_before), suite)
      assert_phase(reader, phase_for(reader_role, remaining_before), suite)

      payload = data.payload <> <<message_index>>

      message =
        writer
        |> Decibel.handshake_encrypt(fragment(payload, data.variant + message_index))
        |> binary()

      assert_phase(writer, phase_for(writer_role, remaining_after), suite)

      assert_decryption_error(:truncated, fn ->
        Decibel.handshake_decrypt(reader, fragment(<<>>, data.variant + message_index))
      end)

      assert_phase(reader, :handshake_read, suite)

      assert_authenticated_failure(pattern, message_index, reader, message, data.variant, suite)

      assert payload ==
               reader
               |> Decibel.handshake_decrypt(fragment(message, data.variant + message_index + 2))
               |> binary()

      assert_phase(reader, phase_for(reader_role, remaining_after), suite)
    end)

    assert Decibel.handshake_complete?(initiator)
    assert Decibel.handshake_complete?(responder)
    assert byte_size(Decibel.handshake_hash(initiator)) == suite.hash_len
    assert Decibel.handshake_hash(initiator) == Decibel.handshake_hash(responder)

    send_with_failed_retries(initiator, responder, data.payload, data.aad, data.variant)

    case pattern.mode do
      :interactive ->
        send_with_failed_retries(responder, initiator, data.payload, data.aad, data.variant + 1)
        assert :ok == Decibel.rekey(responder, :out)
        assert :ok == Decibel.rekey(initiator, :in)
        assert :ok == Decibel.set_nonce(responder, :out, Decibel.nonce(responder, :out) + 2)
        assert :ok == Decibel.set_nonce(initiator, :in, Decibel.nonce(initiator, :in) + 2)
        send_without_failure(responder, initiator, data.payload, data.aad, data.variant + 2)

      :one_way ->
        assert_one_way_rejections(initiator, responder)
    end

    assert :ok == Decibel.rekey(initiator, :out)
    assert :ok == Decibel.rekey(responder, :in)
    assert :ok == Decibel.set_nonce(initiator, :out, Decibel.nonce(initiator, :out) + 2)
    assert :ok == Decibel.set_nonce(responder, :in, Decibel.nonce(responder, :in) + 2)
    send_without_failure(initiator, responder, data.payload, data.aad, data.variant + 3)

    assert :ok == Decibel.close(initiator)
    assert_closed(initiator)
    assert :ok == Decibel.close(responder)
    assert_closed(responder)
  end

  defp send_with_failed_retries(sender, recipient, payload, aad, variant) do
    sender_nonce = Decibel.nonce(sender, :out)
    recipient_nonce = Decibel.nonce(recipient, :in)

    ciphertext = sender |> Decibel.encrypt(fragment(payload, variant), fragment(aad, variant + 1)) |> binary()
    assert Decibel.nonce(sender, :out) == sender_nonce + 1

    for operation <- [
          fn ->
            Decibel.decrypt(
              recipient,
              fragment(flip_last_byte(ciphertext), variant + 2),
              fragment(aad, variant + 1)
            )
          end,
          fn ->
            Decibel.decrypt(
              recipient,
              fragment(ciphertext, variant + 3),
              ["wrong", fragment(aad, variant + 1)]
            )
          end
        ] do
      assert_decryption_error(:authentication_failed, operation)
      assert Decibel.nonce(recipient, :in) == recipient_nonce
    end

    assert payload ==
             recipient
             |> Decibel.decrypt(fragment(ciphertext, variant + 4), fragment(aad, variant + 1))
             |> binary()

    assert Decibel.nonce(recipient, :in) == recipient_nonce + 1
  end

  defp assert_authenticated_failure(pattern, message_index, reader, message, variant, suite) do
    if message_index in pattern.authenticated do
      assert_decryption_error(:authentication_failed, fn ->
        Decibel.handshake_decrypt(reader, fragment(flip_last_byte(message), variant + message_index + 1))
      end)

      assert_phase(reader, :handshake_read, suite)
    end
  end

  defp send_without_failure(sender, recipient, payload, aad, variant) do
    ciphertext = Decibel.encrypt(sender, fragment(payload, variant), fragment(aad, variant + 1))

    assert payload ==
             recipient
             |> Decibel.decrypt(fragment(binary(ciphertext), variant + 2), fragment(aad, variant + 1))
             |> binary()
  end

  defp assert_one_way_rejections(initiator, responder) do
    permitted = {Decibel.nonce(initiator, :out), Decibel.nonce(responder, :in)}

    for {direction, operation} <- [
          {:in, fn -> Decibel.decrypt(initiator, <<>>) end},
          {:in, fn -> Decibel.rekey(initiator, :in) end},
          {:in, fn -> Decibel.nonce(initiator, :in) end},
          {:in, fn -> Decibel.set_nonce(initiator, :in, 0) end},
          {:out, fn -> Decibel.encrypt(responder, <<>>) end},
          {:out, fn -> Decibel.rekey(responder, :out) end},
          {:out, fn -> Decibel.nonce(responder, :out) end},
          {:out, fn -> Decibel.set_nonce(responder, :out, 0) end}
        ] do
      error = assert_raise TransportDirectionError, operation
      assert error.direction == direction
      assert {Decibel.nonce(initiator, :out), Decibel.nonce(responder, :in)} == permitted
    end
  end

  defp assert_phase(session, phase, suite) do
    complete? = phase == :transport
    assert Decibel.handshake_complete?(session) == complete?
    assert deprecated_call(:is_handshake_complete?, [session]) == complete?
    assert deprecated_call(:get_handshake_hash, [session]) == Decibel.handshake_hash(session)
    assert deprecated_call(:get_remote_key, [session]) == Decibel.remote_key(session)

    if complete? do
      assert byte_size(Decibel.handshake_hash(session)) == suite.hash_len
      assert_nonce_alias(session)
    else
      assert Decibel.handshake_hash(session) == nil
    end

    case phase do
      :handshake_write ->
        assert_wrong_phase(
          fn -> Decibel.handshake_decrypt(session, <<>>) end,
          :handshake_decrypt,
          :handshake_read,
          phase
        )

        assert_transport_wrong_phase(session, phase)

      :handshake_read ->
        assert_wrong_phase(
          fn -> Decibel.handshake_encrypt(session) end,
          :handshake_encrypt,
          :handshake_write,
          phase
        )

        assert_transport_wrong_phase(session, phase)

      :transport ->
        assert_wrong_phase(
          fn -> Decibel.handshake_encrypt(session) end,
          :handshake_encrypt,
          :handshake_write,
          phase
        )

        assert_wrong_phase(
          fn -> Decibel.handshake_decrypt(session, <<>>) end,
          :handshake_decrypt,
          :handshake_read,
          phase
        )
    end
  end

  defp assert_transport_wrong_phase(session, actual_phase) do
    for {operation, call} <- transport_operations(session) do
      assert_wrong_phase(call, operation, :transport, actual_phase)
    end
  end

  defp transport_operations(session) do
    [
      encrypt: fn -> Decibel.encrypt(session, <<>>) end,
      decrypt: fn -> Decibel.decrypt(session, <<>>) end,
      rekey_in: fn -> Decibel.rekey(session, :in) end,
      rekey_out: fn -> Decibel.rekey(session, :out) end,
      nonce_in: fn -> Decibel.nonce(session, :in) end,
      nonce_out: fn -> Decibel.nonce(session, :out) end,
      set_nonce_in: fn -> Decibel.set_nonce(session, :in, 0) end,
      set_nonce_out: fn -> Decibel.set_nonce(session, :out, 0) end
    ]
    |> Enum.map(fn {operation, call} -> {canonical_operation(operation), call} end)
  end

  defp canonical_operation(operation) when operation in [:rekey_in, :rekey_out], do: :rekey
  defp canonical_operation(operation) when operation in [:nonce_in, :nonce_out], do: :nonce
  defp canonical_operation(operation) when operation in [:set_nonce_in, :set_nonce_out], do: :set_nonce
  defp canonical_operation(operation), do: operation

  defp assert_wrong_phase(call, operation, expected_phase, actual_phase) do
    message =
      "Session operation #{operation} requires #{expected_phase} phase; " <>
        "current phase is #{actual_phase}"

    error = assert_raise SessionError, message, call
    assert error.reason == :wrong_phase
    assert error.operation == operation
    assert error.expected_phase == expected_phase
    assert error.actual_phase == actual_phase
  end

  defp assert_closed(session) do
    for {_operation, call} <- all_operations(session) do
      error = assert_raise SessionError, "Session is closed", call
      assert error.reason == :closed
      assert error.operation == nil
      assert error.expected_phase == nil
      assert error.actual_phase == nil
    end
  end

  defp assert_nonce_alias(session) do
    {direction, nonce} =
      Enum.find_value([:out, :in], fn direction ->
        try do
          {direction, Decibel.nonce(session, direction)}
        rescue
          _error in TransportDirectionError -> nil
        end
      end)

    assert deprecated_call(:get_nonce, [session, direction]) == nonce
  end

  defp all_operations(session) do
    [
      handshake_encrypt: fn -> Decibel.handshake_encrypt(session) end,
      handshake_decrypt: fn -> Decibel.handshake_decrypt(session, <<>>) end,
      handshake_complete?: fn -> Decibel.handshake_complete?(session) end,
      handshake_hash: fn -> Decibel.handshake_hash(session) end,
      deprecated_handshake_complete?: fn -> deprecated_call(:is_handshake_complete?, [session]) end,
      deprecated_handshake_hash: fn -> deprecated_call(:get_handshake_hash, [session]) end,
      encrypt: fn -> Decibel.encrypt(session, <<>>) end,
      decrypt: fn -> Decibel.decrypt(session, <<>>) end,
      close: fn -> Decibel.close(session) end,
      rekey: fn -> Decibel.rekey(session, :out) end,
      nonce: fn -> Decibel.nonce(session, :out) end,
      deprecated_nonce: fn -> deprecated_call(:get_nonce, [session, :out]) end,
      set_nonce: fn -> Decibel.set_nonce(session, :out, 0) end,
      remote_key: fn -> Decibel.remote_key(session) end,
      deprecated_remote_key: fn -> deprecated_call(:get_remote_key, [session]) end
    ]
  end

  defp new_pair(pattern, suite, prologue) do
    protocol = protocol(pattern.name, suite)
    common = %{prologue: prologue}

    case pattern.name do
      "N" ->
        {responder_public, _private} = responder_static = :crypto.generate_key(:ecdh, suite.curve)

        {
          Decibel.new(protocol, :ini, Map.put(common, :rs, responder_public)),
          Decibel.new(protocol, :rsp, Map.put(common, :s, responder_static))
        }

      name when name in ["XX", "X1X1"] ->
        initiator_static = :crypto.generate_key(:ecdh, suite.curve)
        responder_static = :crypto.generate_key(:ecdh, suite.curve)

        {
          Decibel.new(protocol, :ini, Map.put(common, :s, initiator_static)),
          Decibel.new(protocol, :rsp, Map.put(common, :s, responder_static))
        }

      "NNpsk0" ->
        psk = :crypto.hash(:sha256, protocol)
        keys = Map.put(common, :psks, [psk])
        {Decibel.new(protocol, :ini, keys), Decibel.new(protocol, :rsp, keys)}

      "XXfallback" ->
        {prior_public, _private} = prior_ephemeral = :crypto.generate_key(:ecdh, suite.curve)
        initiator_static = :crypto.generate_key(:ecdh, suite.curve)
        responder_static = :crypto.generate_key(:ecdh, suite.curve)

        {
          Decibel.new(
            protocol,
            :ini,
            common |> Map.put(:e, prior_ephemeral) |> Map.put(:s, initiator_static),
            swap: :rsp
          ),
          Decibel.new(
            protocol,
            :rsp,
            common |> Map.put(:re, prior_public) |> Map.put(:s, responder_static),
            swap: :rsp
          )
        }

      "NN" ->
        {Decibel.new(protocol, :ini, common), Decibel.new(protocol, :rsp, common)}
    end
  end

  defp establish_nn(suite, prologue) do
    pattern = Enum.find(@patterns, &(&1.name == "NN"))
    {initiator, responder} = new_pair(pattern, suite, prologue)

    initiator
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(responder, &1))

    responder
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(initiator, &1))

    {initiator, responder}
  end

  defp generated_data(random_state, run) do
    {payload_size, random_state} = :rand.uniform_s(48, random_state)
    {payload, random_state} = :rand.bytes_s(payload_size, random_state)
    {prologue_size, random_state} = :rand.uniform_s(24, random_state)
    {prologue, random_state} = :rand.bytes_s(prologue_size, random_state)
    {aad_size, random_state} = :rand.uniform_s(24, random_state)
    {aad, random_state} = :rand.bytes_s(aad_size, random_state)
    {variant, random_state} = :rand.uniform_s(5, random_state)

    {%{payload: payload, prologue: prologue, aad: aad, variant: variant + run}, random_state}
  end

  defp fragment(bytes, variant) when is_binary(bytes) do
    case rem(variant, 5) do
      0 ->
        bytes

      1 ->
        [bytes]

      2 ->
        :binary.bin_to_list(bytes)

      3 ->
        split = div(byte_size(bytes), 2)
        <<left::binary-size(split), right::binary>> = bytes
        [<<>>, [left, [<<>>, right]], <<>>]

      4 ->
        case bytes do
          <<>> -> [[], <<>>, []]
          <<first, rest::binary>> -> [[], first, [<<>>, rest], []]
        end
    end
  end

  defp phase_for(_role, []), do: :transport
  defp phase_for(role, [role | _rest]), do: :handshake_write
  defp phase_for(_role, [_other | _rest]), do: :handshake_read

  defp protocol(pattern, suite) do
    "Noise_#{pattern}_#{suite.curve_name}_#{suite.cipher}_#{suite.hash}"
  end

  defp assert_decryption_error(reason, operation) do
    error = assert_raise DecryptionError, "Decryption failed", operation
    assert error.reason == reason
    error
  end

  defp flip_last_byte(message) do
    index = byte_size(message) - 1
    <<prefix::binary-size(index), byte>> = message
    <<prefix::binary, Bitwise.bxor(byte, 1)>>
  end

  defp binary(iodata), do: IO.iodata_to_binary(iodata)
  defp opposite(:ini), do: :rsp
  defp opposite(:rsp), do: :ini

  defp close_all(sessions) do
    for session <- sessions, do: assert(:ok == Decibel.close(session))
  end

  # Dynamic invocation verifies deprecated forwarders without compiler warnings.
  # credo:disable-for-next-line Credo.Check.Refactor.Apply
  defp deprecated_call(name, arguments), do: apply(Decibel, name, arguments)

  defp session_entries do
    Process.get()
    |> Enum.filter(fn
      {_key, %Decibel.Handshake{}} -> true
      {_key, %Decibel.ChannelPair{}} -> true
      {_key, _value} -> false
    end)
    |> Map.new()
  end
end
