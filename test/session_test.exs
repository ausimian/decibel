defmodule Decibel.SessionTest do
  use ExUnit.Case

  alias Decibel.{Session, SessionError}

  @nn_protocol "Noise_NN_25519_ChaChaPoly_BLAKE2s"

  test "owner-aware handles reject every operation from another process" do
    parent = self()

    {owner, monitor} =
      spawn_monitor(fn ->
        session = Decibel.new(@nn_protocol, :ini)
        send(parent, {:session, self(), session})

        receive do
          :continue ->
            message = Decibel.handshake_encrypt(session)
            send(parent, {:owner_message, self(), message})
        end

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:session, ^owner, session}

    for {_operation, call} <- all_operations(session) do
      assert_session_error(call, :not_owner, "Session is owned by another process")
    end

    tasks =
      for _index <- 1..8 do
        Task.async(fn -> capture_session_error(fn -> Decibel.get_handshake_hash(session) end) end)
      end

    for task <- tasks do
      assert %SessionError{reason: :not_owner} = Task.await(task)
    end

    send(owner, :continue)
    assert_receive {:owner_message, ^owner, message}
    assert IO.iodata_length(message) == 32

    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}

    assert_session_error(
      fn -> Decibel.get_handshake_hash(session) end,
      :not_owner,
      "Session is owned by another process"
    )
  end

  test "legacy references, malformed terms, and never-issued handles are unknown" do
    unknown_values = [make_ref(), :not_a_session, %{owner: self(), id: make_ref()}]

    for unknown <- unknown_values,
        {_operation, call} <- all_operations(unknown) do
      assert_session_error(call, :unknown, "Unknown Decibel session")
    end

    invalid_proof = :crypto.strong_rand_bytes(32)
    invalid_status = :atomics.new(1, signed: false)

    never_issued =
      struct!(Session,
        owner: self(),
        id: make_ref(),
        status: invalid_status,
        proof: invalid_proof
      )

    for {_operation, call} <- all_operations(never_issued) do
      assert_session_error(call, :unknown, "Unknown Decibel session")
    end

    foreign_owner = spawn(fn -> receive do: (:stop -> :ok) end)

    foreign_never_issued =
      struct!(Session,
        owner: foreign_owner,
        id: make_ref(),
        status: invalid_status,
        proof: invalid_proof
      )

    for {_operation, call} <- all_operations(foreign_never_issued) do
      assert_session_error(call, :unknown, "Unknown Decibel session")
    end

    send(foreign_owner, :stop)
  end

  test "closing a handshake discards sensitive state and leaves a stable marker" do
    static = :crypto.generate_key(:ecdh, :x25519)
    psk = :crypto.strong_rand_bytes(32)

    session =
      Decibel.new(
        "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s",
        :ini,
        %{s: static, psks: [psk]}
      )

    assert inspect(session) =~ "#Decibel.Session<owner:"
    refute inspect(session) =~ "#Reference"
    assert :ok == Decibel.close(session)

    refute Enum.any?(Process.get(), fn
             {{Session, _id}, _state} -> true
             {_key, %Decibel.Handshake{}} -> true
             {_key, %Decibel.ChannelPair{}} -> true
             {_key, _value} -> false
           end)

    for {_operation, call} <- all_operations(session) do
      assert_session_error(call, :closed, "Session is closed")
    end

    task =
      Task.async(fn ->
        capture_session_error(fn -> Decibel.get_handshake_hash(session) end)
      end)

    assert %SessionError{reason: :not_owner} = Task.await(task)
  end

  test "closing a transport session rejects every later operation" do
    {initiator, responder} = establish_nn(@nn_protocol)

    assert :ok == Decibel.close(initiator)

    for {_operation, call} <- all_operations(initiator) do
      assert_session_error(call, :closed, "Session is closed")
    end

    assert :ok == Decibel.close(responder)
  end

  test "closing sessions does not retain tombstones in a long-lived owner" do
    for _index <- 1..100 do
      session = Decibel.new(@nn_protocol, :ini)
      assert :ok == Decibel.close(session)
    end

    refute Enum.any?(Process.get(), fn
             {{Session, _id}, _state} -> true
             {_key, _value} -> false
           end)
  end

  test "issued handles survive signing component restarts without serialized validation" do
    session = Decibel.new(@nn_protocol, :ini)
    original_keys = Process.whereis(Decibel.SessionKeys)

    on_exit(fn ->
      if is_nil(Process.whereis(Decibel.SessionKeys)) do
        Supervisor.restart_child(Decibel.Supervisor, Decibel.SessionKeys)
      end
    end)

    assert :ok == Supervisor.terminate_child(Decibel.Supervisor, Decibel.SessionKeys)
    assert IO.iodata_length(Decibel.handshake_encrypt(session)) == 32

    task =
      Task.async(fn ->
        capture_session_error(fn -> Decibel.get_handshake_hash(session) end)
      end)

    assert %SessionError{reason: :not_owner} = Task.await(task)

    assert {:ok, restarted_keys} =
             Supervisor.restart_child(Decibel.Supervisor, Decibel.SessionKeys)

    refute restarted_keys == original_keys
    assert :ok == await_session_keys(100)
    assert false == Decibel.is_handshake_complete?(session)
    assert :ok == Decibel.close(session)

    new_session = Decibel.new(@nn_protocol, :ini)
    assert IO.iodata_length(Decibel.handshake_encrypt(new_session)) == 32
    assert :ok == Decibel.close(new_session)
  end

  test "wrong handshake turns and phases raise stable errors without advancing state" do
    initiator = Decibel.new(@nn_protocol, :ini)
    responder = Decibel.new(@nn_protocol, :rsp)

    assert_wrong_phase(
      fn -> Decibel.handshake_decrypt(initiator, <<>>) end,
      :handshake_decrypt,
      :handshake_read,
      :handshake_write
    )

    assert_wrong_phase(
      fn -> Decibel.handshake_encrypt(responder) end,
      :handshake_encrypt,
      :handshake_write,
      :handshake_read
    )

    for {operation, call} <- transport_operations(initiator) do
      assert_wrong_phase(call, operation, :transport, :handshake_write)
    end

    assert false == Decibel.is_handshake_complete?(initiator)
    assert nil == Decibel.get_handshake_hash(initiator)
    assert nil == Decibel.get_remote_key(initiator)

    message1 = Decibel.handshake_encrypt(initiator)

    assert_wrong_phase(
      fn -> Decibel.handshake_encrypt(initiator) end,
      :handshake_encrypt,
      :handshake_write,
      :handshake_read
    )

    assert "" == Decibel.handshake_decrypt(responder, message1)

    assert_wrong_phase(
      fn -> Decibel.handshake_decrypt(responder, message1) end,
      :handshake_decrypt,
      :handshake_read,
      :handshake_write
    )

    message2 = Decibel.handshake_encrypt(responder)
    assert "" == Decibel.handshake_decrypt(initiator, message2)

    for session <- [initiator, responder] do
      assert Decibel.is_handshake_complete?(session)
      assert is_binary(Decibel.get_handshake_hash(session))

      assert_wrong_phase(
        fn -> Decibel.handshake_encrypt(session) end,
        :handshake_encrypt,
        :handshake_write,
        :transport
      )

      assert_wrong_phase(
        fn -> Decibel.handshake_decrypt(session, <<>>) end,
        :handshake_decrypt,
        :handshake_read,
        :transport
      )
    end

    ciphertext = Decibel.encrypt(initiator, "after rejected transitions")
    assert "after rejected transitions" == Decibel.decrypt(responder, ciphertext)

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "session lifecycle is consistent across curves, ciphers, and hashes" do
    for {protocol, hash_length} <- [
          {"Noise_NN_25519_ChaChaPoly_SHA256", 32},
          {"Noise_NN_25519_ChaChaPoly_BLAKE2s", 32},
          {"Noise_NN_448_AESGCM_SHA512", 64},
          {"Noise_NN_448_AESGCM_BLAKE2b", 64}
        ] do
      initiator = Decibel.new(protocol, :ini)
      responder = Decibel.new(protocol, :rsp)

      assert_wrong_phase(
        fn -> Decibel.encrypt(initiator, "too early") end,
        :encrypt,
        :transport,
        :handshake_write
      )

      message1 = Decibel.handshake_encrypt(initiator)
      assert "" == Decibel.handshake_decrypt(responder, message1)
      message2 = Decibel.handshake_encrypt(responder)
      assert "" == Decibel.handshake_decrypt(initiator, message2)

      assert byte_size(Decibel.get_handshake_hash(initiator)) == hash_length
      assert byte_size(Decibel.get_handshake_hash(responder)) == hash_length

      ciphertext = Decibel.encrypt(initiator, protocol)
      assert protocol == Decibel.decrypt(responder, ciphertext)

      Decibel.close(initiator)
      Decibel.close(responder)
    end
  end

  test "one-way 448 session crosses directly into transport" do
    {responder_public, _private} = responder_static = :crypto.generate_key(:ecdh, :x448)
    protocol = "Noise_N_448_AESGCM_SHA512"
    initiator = Decibel.new(protocol, :ini, %{rs: responder_public})
    responder = Decibel.new(protocol, :rsp, %{s: responder_static})

    message = Decibel.handshake_encrypt(initiator)
    assert Decibel.is_handshake_complete?(initiator)
    assert "" == Decibel.handshake_decrypt(responder, message)
    assert Decibel.is_handshake_complete?(responder)
    assert byte_size(Decibel.get_handshake_hash(initiator)) == 64

    ciphertext = Decibel.encrypt(initiator, "one way")
    assert "one way" == Decibel.decrypt(responder, ciphertext)

    assert_raise Decibel.TransportDirectionError, fn ->
      Decibel.encrypt(responder, "wrong direction")
    end

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "unsafe vector sessions share ownership and phase validation" do
    parent = self()
    ephemeral = :crypto.generate_key(:ecdh, :x25519)

    owner =
      spawn(fn ->
        session = Decibel.Unsafe.new(@nn_protocol, :ini, %{e: ephemeral})
        send(parent, {:unsafe_session, self(), session})

        error =
          capture_session_error(fn ->
            Decibel.handshake_decrypt(session, <<>>)
          end)

        send(parent, {:unsafe_phase_error, self(), error})
        Decibel.close(session)
      end)

    assert_receive {:unsafe_session, ^owner, session}

    assert_session_error(
      fn -> Decibel.get_handshake_hash(session) end,
      :not_owner,
      "Session is owned by another process"
    )

    assert_receive {:unsafe_phase_error, ^owner,
                    %SessionError{
                      reason: :wrong_phase,
                      operation: :handshake_decrypt,
                      expected_phase: :handshake_read,
                      actual_phase: :handshake_write
                    }}
  end

  test "invalid handles take precedence over operation argument validation" do
    session = Decibel.new(@nn_protocol, :ini)
    assert :ok == Decibel.close(session)

    assert_session_error(
      fn -> Decibel.encrypt(session, :not_iodata) end,
      :closed,
      "Session is closed"
    )

    assert_session_error(
      fn -> Decibel.set_nonce(session, :sideways, :not_a_nonce) end,
      :closed,
      "Session is closed"
    )

    unknown = make_ref()

    assert_session_error(
      fn -> Decibel.rekey(unknown, :sideways) end,
      :unknown,
      "Unknown Decibel session"
    )
  end

  defp establish_nn(protocol) do
    initiator = Decibel.new(protocol, :ini)
    responder = Decibel.new(protocol, :rsp)

    initiator
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(responder, &1))

    responder
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(initiator, &1))

    {initiator, responder}
  end

  defp all_operations(session) do
    [
      handshake_encrypt: fn -> Decibel.handshake_encrypt(session) end,
      handshake_decrypt: fn -> Decibel.handshake_decrypt(session, <<>>) end,
      is_handshake_complete?: fn -> Decibel.is_handshake_complete?(session) end,
      get_handshake_hash: fn -> Decibel.get_handshake_hash(session) end,
      encrypt: fn -> Decibel.encrypt(session, "plaintext") end,
      decrypt: fn -> Decibel.decrypt(session, <<>>) end,
      close: fn -> Decibel.close(session) end,
      rekey: fn -> Decibel.rekey(session, :out) end,
      get_nonce: fn -> Decibel.get_nonce(session, :out) end,
      set_nonce: fn -> Decibel.set_nonce(session, :out, 0) end,
      get_remote_key: fn -> Decibel.get_remote_key(session) end
    ]
  end

  defp transport_operations(session) do
    [
      encrypt: fn -> Decibel.encrypt(session, "plaintext") end,
      decrypt: fn -> Decibel.decrypt(session, <<>>) end,
      rekey: fn -> Decibel.rekey(session, :out) end,
      get_nonce: fn -> Decibel.get_nonce(session, :out) end,
      set_nonce: fn -> Decibel.set_nonce(session, :out, 0) end
    ]
  end

  defp assert_wrong_phase(call, operation, expected_phase, actual_phase) do
    message =
      "Session operation #{operation} requires #{expected_phase} phase; " <>
        "current phase is #{actual_phase}"

    error = assert_session_error(call, :wrong_phase, message)
    assert error.operation == operation
    assert error.expected_phase == expected_phase
    assert error.actual_phase == actual_phase
  end

  defp assert_session_error(call, reason, message) do
    error = assert_raise SessionError, message, call
    assert error.reason == reason

    if reason != :wrong_phase do
      assert error.operation == nil
      assert error.expected_phase == nil
      assert error.actual_phase == nil
    end

    refute error.message =~ "#PID"
    refute error.message =~ "#Reference"
    refute error.message =~ "Decibel.Handshake"
    refute error.message =~ "Decibel.ChannelPair"
    error
  end

  defp capture_session_error(call) do
    call.()
  rescue
    error in SessionError -> error
  end

  defp await_session_keys(0), do: flunk("session keys did not recover")

  defp await_session_keys(attempts_left) do
    case Decibel.SessionKeys.public_key() do
      {:ok, _public_key} ->
        :ok

      :error ->
        Process.sleep(1)
        await_session_keys(attempts_left - 1)
    end
  end
end
