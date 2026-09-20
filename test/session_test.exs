defmodule Decibel.SessionTest do
  use ExUnit.Case

  alias Decibel.{Session, SessionError}

  @nn_protocol "Noise_NN_25519_ChaChaPoly_BLAKE2s"

  test "owner-aware handles reject every operation from concurrent foreign callers" do
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
      for {operation, call} <- all_operations(session) do
        Task.async(fn -> {operation, capture_session_error(call)} end)
      end

    for task <- tasks do
      assert {_operation, %SessionError{reason: :not_owner}} = Task.await(task)
    end

    send(owner, :continue)
    assert_receive {:owner_message, ^owner, message}
    assert IO.iodata_length(message) == 32

    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}

    for {_operation, call} <- all_operations(session) do
      assert_session_error(call, :not_owner, "Session is owned by another process")
    end
  end

  test "legacy, malformed, and absent owner-local handles are unknown" do
    malformed_session = struct(Session, owner: :not_a_pid, id: make_ref())

    unknown_values = [
      make_ref(),
      :not_a_session,
      %{owner: self(), id: make_ref()},
      malformed_session,
      struct!(Session, owner: self(), id: make_ref())
    ]

    for unknown <- unknown_values,
        {_operation, call} <- all_operations(unknown) do
      assert_session_error(call, :unknown, "Unknown Decibel session")
    end
  end

  test "a well-shaped foreign-looking handle is classified only by its owner PID" do
    owner = spawn(fn -> receive do: (:stop -> :ok) end)
    handle = struct!(Session, owner: owner, id: make_ref())

    for {_operation, call} <- all_operations(handle) do
      assert_session_error(call, :not_owner, "Session is owned by another process")
    end

    send(owner, :stop)
  end

  test "closing a handshake discards state and leaves only a small marker" do
    static = :crypto.generate_key(:ecdh, :x25519)
    psk = :crypto.strong_rand_bytes(32)

    session =
      Decibel.new(
        "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s",
        :ini,
        %{s: static, psks: [psk]}
      )

    assert Map.keys(session) |> Enum.sort() == [:__struct__, :id, :owner]
    assert inspect(session) =~ "#Decibel.Session<owner:"
    refute inspect(session) =~ "#Reference"

    assert :ok == Decibel.close(session)

    assert [{{Session, _id}, :closed}] = session_entries()

    for {_operation, call} <- all_operations(session) do
      assert_session_error(call, :closed, "Session is closed")
    end

    assert [{{Session, _id}, :closed}] = session_entries()

    task = Task.async(fn -> capture_session_error(fn -> Decibel.close(session) end) end)
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

  test "wrong operations fail at every handshake turn without advancing state" do
    initiator = Decibel.new(@nn_protocol, :ini)
    responder = Decibel.new(@nn_protocol, :rsp)

    assert_phase_rejections(initiator, :handshake_write)
    assert_phase_rejections(responder, :handshake_read)
    assert_live_accessors(initiator, false)
    assert_live_accessors(responder, false)

    message1 = Decibel.handshake_encrypt(initiator)
    assert_phase_rejections(initiator, :handshake_read)
    assert_phase_rejections(responder, :handshake_read)

    assert "" == Decibel.handshake_decrypt(responder, message1)
    assert_phase_rejections(initiator, :handshake_read)
    assert_phase_rejections(responder, :handshake_write)

    message2 = Decibel.handshake_encrypt(responder)
    assert_phase_rejections(initiator, :handshake_read)
    assert_phase_rejections(responder, :transport)

    assert "" == Decibel.handshake_decrypt(initiator, message2)
    assert_phase_rejections(initiator, :transport)
    assert_phase_rejections(responder, :transport)
    assert_live_accessors(initiator, true)
    assert_live_accessors(responder, true)

    ciphertext = Decibel.encrypt(initiator, "after rejected transitions")
    assert "after rejected transitions" == Decibel.decrypt(responder, ciphertext)

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "failed handshake decryption leaves the expected phase unchanged" do
    initiator = Decibel.new(@nn_protocol, :ini)
    responder = Decibel.new(@nn_protocol, :rsp)
    valid_message = Decibel.handshake_encrypt(initiator)

    error =
      assert_raise Decibel.DecryptionError, "Decryption failed", fn ->
        Decibel.handshake_decrypt(responder, <<>>)
      end

    assert error.reason == :truncated

    assert_wrong_phase(
      fn -> Decibel.handshake_encrypt(responder) end,
      :handshake_encrypt,
      :handshake_write,
      :handshake_read
    )

    assert "" == Decibel.handshake_decrypt(responder, valid_message)

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "session lifecycle covers every supported curve, cipher, and hash combination" do
    for curve <- ["25519", "448"],
        cipher <- ["ChaChaPoly", "AESGCM"],
        hash <- ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"] do
      protocol = "Noise_NN_#{curve}_#{cipher}_#{hash}"
      {initiator, responder} = establish_nn(protocol)
      hash_length = if hash in ["SHA256", "BLAKE2s"], do: 32, else: 64

      assert byte_size(Decibel.handshake_hash(initiator)) == hash_length
      assert byte_size(Decibel.handshake_hash(responder)) == hash_length

      ciphertext = Decibel.encrypt(initiator, protocol)
      assert protocol == Decibel.decrypt(responder, ciphertext)

      assert :ok == Decibel.close(initiator)
      assert :ok == Decibel.close(responder)
    end
  end

  test "one-way 448 session crosses directly into transport" do
    {responder_public, _private} = responder_static = :crypto.generate_key(:ecdh, :x448)
    protocol = "Noise_N_448_AESGCM_SHA512"
    initiator = Decibel.new(protocol, :ini, %{rs: responder_public})
    responder = Decibel.new(protocol, :rsp, %{s: responder_static})

    assert Decibel.remote_key(initiator) == responder_public
    assert Decibel.remote_key(responder) == nil
    assert_phase_rejections(initiator, :handshake_write)
    assert_phase_rejections(responder, :handshake_read)

    message = Decibel.handshake_encrypt(initiator)
    assert_phase_rejections(initiator, :transport)
    assert "" == Decibel.handshake_decrypt(responder, message)
    assert_phase_rejections(responder, :transport)
    assert byte_size(Decibel.handshake_hash(initiator)) == 64
    assert byte_size(Decibel.handshake_hash(responder)) == 64
    assert Decibel.nonce(initiator, :out) == 0
    assert Decibel.nonce(responder, :in) == 0

    ciphertext = Decibel.encrypt(initiator, "one way")
    assert "one way" == Decibel.decrypt(responder, ciphertext)

    assert_raise Decibel.TransportDirectionError, fn ->
      Decibel.encrypt(responder, "wrong direction")
    end

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "unsafe vector sessions share ownership, phase, inspection, and close behavior" do
    parent = self()
    ephemeral = :crypto.generate_key(:ecdh, :x25519)

    owner =
      spawn(fn ->
        session = Decibel.Unsafe.new(@nn_protocol, :ini, %{e: ephemeral})
        send(parent, {:unsafe_session, self(), session, inspect(session)})

        phase_error =
          capture_session_error(fn ->
            Decibel.handshake_decrypt(session, <<>>)
          end)

        send(parent, {:unsafe_phase_error, self(), phase_error})
        :ok = Decibel.close(session)
        send(parent, {:unsafe_closed_error, self(), capture_session_error(fn -> Decibel.close(session) end)})
      end)

    assert_receive {:unsafe_session, ^owner, session, inspected}
    assert inspected =~ "#Decibel.Session<owner:"
    refute inspected =~ "#Reference"

    assert_session_error(
      fn -> Decibel.handshake_hash(session) end,
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

    assert_receive {:unsafe_closed_error, ^owner, %SessionError{reason: :closed}}
  end

  test "session and phase validation precede operation argument validation" do
    closed = Decibel.new(@nn_protocol, :ini)
    assert :ok == Decibel.close(closed)

    assert_session_error(
      fn -> Decibel.encrypt(closed, :not_iodata) end,
      :closed,
      "Session is closed"
    )

    assert_session_error(
      fn -> Decibel.set_nonce(closed, :sideways, :not_a_nonce) end,
      :closed,
      "Session is closed"
    )

    unknown = make_ref()

    assert_session_error(
      fn -> Decibel.rekey(unknown, :sideways) end,
      :unknown,
      "Unknown Decibel session"
    )

    handshake = Decibel.new(@nn_protocol, :ini)

    assert_wrong_phase(
      fn -> Decibel.encrypt(handshake, :not_iodata) end,
      :encrypt,
      :transport,
      :handshake_write
    )

    assert_wrong_phase(
      fn -> Decibel.set_nonce(handshake, :sideways, :not_a_nonce) end,
      :set_nonce,
      :transport,
      :handshake_write
    )

    assert_wrong_phase(
      fn -> deprecated_call(:get_nonce, [handshake, :out]) end,
      :nonce,
      :transport,
      :handshake_write
    )

    Decibel.close(handshake)

    {initiator, responder} = establish_nn(@nn_protocol)

    for call <- [
          fn -> Decibel.rekey(initiator, :sideways) end,
          fn -> Decibel.nonce(initiator, :sideways) end,
          fn -> Decibel.set_nonce(initiator, :sideways, 0) end
        ] do
      assert_raise ArgumentError, "direction must be :in or :out, got: :sideways", call
    end

    assert Decibel.nonce(initiator, :out) == 0
    Decibel.close(initiator)
    Decibel.close(responder)
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

    assert Decibel.handshake_complete?(initiator)
    assert Decibel.handshake_complete?(responder)

    {initiator, responder}
  end

  defp all_operations(session) do
    [
      handshake_encrypt: fn -> Decibel.handshake_encrypt(session) end,
      handshake_decrypt: fn -> Decibel.handshake_decrypt(session, <<>>) end,
      handshake_complete?: fn -> Decibel.handshake_complete?(session) end,
      handshake_hash: fn -> Decibel.handshake_hash(session) end,
      deprecated_handshake_complete?: fn -> deprecated_call(:is_handshake_complete?, [session]) end,
      deprecated_handshake_hash: fn -> deprecated_call(:get_handshake_hash, [session]) end,
      encrypt: fn -> Decibel.encrypt(session, "plaintext") end,
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

  defp transport_operations(session) do
    [
      encrypt: fn -> Decibel.encrypt(session, "plaintext") end,
      decrypt: fn -> Decibel.decrypt(session, <<>>) end,
      rekey: fn -> Decibel.rekey(session, :out) end,
      nonce: fn -> Decibel.nonce(session, :out) end,
      set_nonce: fn -> Decibel.set_nonce(session, :out, 0) end
    ]
  end

  defp assert_phase_rejections(session, :handshake_write) do
    assert_wrong_phase(
      fn -> Decibel.handshake_decrypt(session, <<>>) end,
      :handshake_decrypt,
      :handshake_read,
      :handshake_write
    )

    assert_transport_rejections(session, :handshake_write)
  end

  defp assert_phase_rejections(session, :handshake_read) do
    assert_wrong_phase(
      fn -> Decibel.handshake_encrypt(session) end,
      :handshake_encrypt,
      :handshake_write,
      :handshake_read
    )

    assert_transport_rejections(session, :handshake_read)
  end

  defp assert_phase_rejections(session, :transport) do
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

  defp assert_transport_rejections(session, actual_phase) do
    for {operation, call} <- transport_operations(session) do
      assert_wrong_phase(call, operation, :transport, actual_phase)
    end
  end

  defp assert_live_accessors(session, complete?) do
    assert Decibel.handshake_complete?(session) == complete?
    assert is_binary(Decibel.handshake_hash(session)) == complete?
    assert Decibel.remote_key(session) == nil
  end

  # Dynamic invocation verifies deprecated forwarders without compiler warnings.
  # credo:disable-for-next-line Credo.Check.Refactor.Apply
  defp deprecated_call(name, arguments), do: apply(Decibel, name, arguments)

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

  defp session_entries do
    Enum.filter(Process.get(), fn
      {{Session, _id}, _value} -> true
      {_key, _value} -> false
    end)
  end
end
