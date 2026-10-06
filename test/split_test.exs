defmodule Decibel.SplitTest do
  use ExUnit.Case

  alias Decibel.{HandoffError, SessionError, TransportDirectionError}

  @protocol "Noise_XX_25519_ChaChaPoly_BLAKE2s"

  defmodule Holder do
    use GenServer

    def start_link, do: GenServer.start_link(__MODULE__, nil)

    @impl true
    def init(_argument), do: {:ok, nil}

    @impl true
    def handle_call({:accept, ticket}, _from, _session) do
      session = Decibel.accept_handoff(ticket)
      {:reply, session, session}
    end

    def handle_call({:run, fun}, _from, session) do
      result =
        try do
          {:ok, fun.(session)}
        rescue
          error -> {:raised, error}
        end

      {:reply, result, session}
    end
  end

  test "splitting :in moves decryption to the target and keeps encryption with the owner" do
    {initiator, responder} = establish()
    exchange(initiator, responder, 3)
    {:ok, reader} = Holder.start_link()
    source_keys = Enum.sort(Process.get_keys())

    ticket = Decibel.split(responder, :in, reader)
    assert inspect(ticket) == "#Decibel.Handoff<opaque>"
    assert source_keys == Enum.sort(Process.get_keys())
    assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :not_target)

    inbound = GenServer.call(reader, {:accept, ticket})
    assert inbound.owner == reader
    assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :unavailable)

    ciphertext = Decibel.encrypt(initiator, "to reader")
    assert {:ok, "to reader"} == run(reader, &Decibel.decrypt(&1, ciphertext))
    assert {:ok, 4} == run(reader, &Decibel.nonce(&1, :in))

    ciphertext = Decibel.encrypt(responder, "from owner")
    assert "from owner" == Decibel.decrypt(initiator, ciphertext)
    assert 4 == Decibel.nonce(responder, :out)

    assert {:ok, Decibel.handshake_hash(responder)} == run(reader, &Decibel.handshake_hash/1)
    assert {:ok, Decibel.remote_key(responder)} == run(reader, &Decibel.remote_key/1)

    assert_split_direction(fn -> Decibel.decrypt(responder, ciphertext) end, :in)

    assert {:raised, %TransportDirectionError{direction: :out, cause: :split}} =
             run(reader, &Decibel.encrypt(&1, "wrong way"))

    close_all([initiator, responder])
    GenServer.stop(reader)
  end

  test "splitting :out moves encryption to the target and keeps decryption with the owner" do
    {initiator, responder} = establish()
    exchange(initiator, responder, 2)
    {:ok, writer} = Holder.start_link()

    ticket = Decibel.split(initiator, :out, writer)
    _outbound = GenServer.call(writer, {:accept, ticket})

    {:ok, {nonce, ciphertext}} = run(writer, &Decibel.encrypt_with_nonce(&1, "from writer"))
    assert nonce == 2
    assert "from writer" == Decibel.decrypt(responder, ciphertext)

    ciphertext = Decibel.encrypt(responder, "to owner")
    assert "to owner" == Decibel.decrypt(initiator, ciphertext)

    assert_split_direction(fn -> Decibel.encrypt(initiator, "wrong way") end, :out)

    close_all([initiator, responder])
    GenServer.stop(writer)
  end

  test "both halves run concurrently in separate processes" do
    {initiator, responder} = establish()
    {:ok, reader} = Holder.start_link()
    _inbound = GenServer.call(reader, {:accept, Decibel.split(responder, :in, reader)})

    messages = for i <- 1..200, do: "message #{i}"
    inbound = Enum.map(messages, &Decibel.encrypt(initiator, &1))

    decrypting = Task.async(fn -> run(reader, fn session -> Enum.map(inbound, &Decibel.decrypt(session, &1)) end) end)
    outbound = Enum.map(messages, &Decibel.encrypt(responder, &1))

    assert {:ok, messages} == Task.await(decrypting)
    assert messages == Enum.map(outbound, &Decibel.decrypt(initiator, &1))

    close_all([initiator, responder])
    GenServer.stop(reader)
  end

  test "every operation on the moved direction raises without changing the half" do
    {initiator, responder} = establish()
    {:ok, reader} = Holder.start_link()
    _inbound = GenServer.call(reader, {:accept, Decibel.split(responder, :in, reader)})
    ciphertext = Decibel.encrypt(initiator, "inbound")

    for operation <- [
          fn -> Decibel.decrypt(responder, ciphertext) end,
          fn -> Decibel.decrypt(responder, ciphertext, [], nonce: 0) end,
          fn -> Decibel.rekey(responder, :in) end,
          fn -> Decibel.nonce(responder, :in) end,
          fn -> Decibel.set_nonce(responder, :in, 0) end
        ] do
      assert_split_direction(operation, :in)
    end

    for operation <- [
          &Decibel.encrypt(&1, "outbound"),
          &Decibel.encrypt_with_nonce(&1, "outbound"),
          &Decibel.rekey(&1, :out),
          &Decibel.nonce(&1, :out),
          &Decibel.set_nonce(&1, :out, 0)
        ] do
      assert {:raised, %TransportDirectionError{direction: :out, cause: :split}} = run(reader, operation)
    end

    assert 0 == Decibel.nonce(responder, :out)
    assert {:ok, "inbound"} == run(reader, &Decibel.decrypt(&1, ciphertext))

    close_all([initiator, responder])
    GenServer.stop(reader)
  end

  test "a session accepted from a handshake handoff can be split" do
    initiator = Decibel.new(@protocol, :ini, %{s: keypair()})
    responder = Decibel.new(@protocol, :rsp, %{s: keypair()})
    assert "" == Decibel.handshake_decrypt(responder, Decibel.handshake_encrypt(initiator))

    {:ok, owner} = Holder.start_link()
    _accepted = GenServer.call(owner, {:accept, Decibel.handoff(responder, owner)})

    {:ok, message} = run(owner, &Decibel.handshake_encrypt/1)
    assert "" == Decibel.handshake_decrypt(initiator, message)
    message = Decibel.handshake_encrypt(initiator)
    assert {:ok, ""} == run(owner, &Decibel.handshake_decrypt(&1, message))

    {:ok, reader} = Holder.start_link()
    {:ok, ticket} = run(owner, &Decibel.split(&1, :in, reader))
    inbound = GenServer.call(reader, {:accept, ticket})

    ciphertext = Decibel.encrypt(initiator, "split after handoff")
    assert {:ok, "split after handoff"} == run(reader, &Decibel.decrypt(&1, ciphertext))
    {:ok, ciphertext} = run(owner, &Decibel.encrypt(&1, "still outbound"))
    assert "still outbound" == Decibel.decrypt(initiator, ciphertext)

    assert {:raised, %ArgumentError{message: "a split transport has only one direction and cannot be split again"}} =
             run(reader, &Decibel.split(&1, :out, owner))

    assert {:raised, %SessionError{reason: :wrong_phase, operation: :handoff, actual_phase: :transport}} =
             run(reader, &Decibel.handoff(&1, owner))

    assert inbound.owner == reader
    Decibel.close(initiator)
    GenServer.stop(owner)
    GenServer.stop(reader)
  end

  test "invalid splits raise and leave both directions with the owner" do
    {initiator, responder} = establish()
    target = self()

    task = Task.async(fn -> capture(fn -> Decibel.split(responder, :in, target) end) end)
    assert %SessionError{reason: :not_owner} = Task.await(task)

    assert_raise ArgumentError, "direction must be :in or :out, got: :both", fn ->
      Decibel.split(responder, :both, target)
    end

    assert_handoff_error(fn -> Decibel.split(responder, :in, :not_a_pid) end, :invalid_target)
    dead = spawn(fn -> :ok end)
    monitor = Process.monitor(dead)
    assert_receive {:DOWN, ^monitor, :process, ^dead, _reason}
    assert_handoff_error(fn -> Decibel.split(responder, :out, dead) end, :invalid_target)

    assert "intact" == Decibel.decrypt(responder, Decibel.encrypt(initiator, "intact"))
    assert "intact" == Decibel.decrypt(initiator, Decibel.encrypt(responder, "intact"))

    {:ok, reader} = Holder.start_link()
    _inbound = GenServer.call(reader, {:accept, Decibel.split(responder, :in, reader)})

    assert_raise ArgumentError, "a split transport has only one direction and cannot be split again", fn ->
      Decibel.split(responder, :out, target)
    end

    close_all([initiator, responder])
    assert_session_error(fn -> Decibel.split(responder, :in, target) end, :closed)
    GenServer.stop(reader)
  end

  test "splitting during the handshake raises wrong_phase" do
    initiator = Decibel.new(@protocol, :ini, %{s: keypair()})

    error = assert_session_error(fn -> Decibel.split(initiator, :in, self()) end, :wrong_phase)
    assert error.operation == :split
    assert error.expected_phase == :transport
    assert error.actual_phase == :handshake_write

    Decibel.close(initiator)
  end

  test "one-way transports cannot be split" do
    {responder_public, _private} = responder_static = keypair()
    initiator = Decibel.new("Noise_N_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: responder_public})
    responder = Decibel.new("Noise_N_25519_ChaChaPoly_BLAKE2s", :rsp, %{s: responder_static})
    assert "" == Decibel.handshake_decrypt(responder, Decibel.handshake_encrypt(initiator))

    for session <- [initiator, responder], direction <- [:in, :out] do
      assert_raise ArgumentError, "a one-way transport has only one direction and cannot be split", fn ->
        Decibel.split(session, direction, self())
      end
    end

    assert "one way" == Decibel.decrypt(responder, Decibel.encrypt(initiator, "one way"))
    close_all([initiator, responder])
  end

  test "a discarded ticket loses the moved direction and keeps the owner's half" do
    for fate <- [:target_exit, :expiry] do
      {initiator, responder} = establish()
      target = spawn(fn -> receive do: (:stop -> :ok) end)
      ticket = Decibel.split(responder, :in, target)
      monitor = Process.monitor(ticket.server)

      case fate do
        :target_exit ->
          send(target, :stop)

        :expiry ->
          %{timer: timer} = :sys.get_state(ticket.server)
          send(ticket.server, {:timeout, timer, :expire})
      end

      assert_receive {:DOWN, ^monitor, :process, _server, :normal}
      assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :unavailable)

      assert "kept" == Decibel.decrypt(initiator, Decibel.encrypt(responder, "kept"))
      assert_split_direction(fn -> Decibel.nonce(responder, :in) end, :in)

      if fate == :expiry, do: send(target, :stop)
      close_all([initiator, responder])
    end
  end

  test "closing one half or exiting its owner leaves the other half usable" do
    {initiator, responder} = establish()
    {:ok, reader} = Holder.start_link()
    _inbound = GenServer.call(reader, {:accept, Decibel.split(responder, :in, reader)})

    assert {:ok, :ok} == run(reader, &Decibel.close/1)
    assert "after close" == Decibel.decrypt(initiator, Decibel.encrypt(responder, "after close"))
    GenServer.stop(reader)

    {:ok, writer} = Holder.start_link()
    _outbound = GenServer.call(writer, {:accept, Decibel.split(initiator, :out, writer)})
    GenServer.stop(writer)
    assert "after exit" == Decibel.decrypt(initiator, Decibel.encrypt(responder, "after exit"))

    close_all([initiator, responder])
  end

  test "split ticket status does not expose transport state" do
    {initiator, responder} = establish()
    {:ok, reader} = Holder.start_link()
    ticket = Decibel.split(responder, :in, reader)

    status = inspect(:sys.get_status(ticket.server))
    assert status =~ "redacted"
    refute status =~ "Decibel.ChannelPair"
    refute status =~ "Decibel.Cipher"

    _inbound = GenServer.call(reader, {:accept, ticket})
    close_all([initiator, responder])
    GenServer.stop(reader)
  end

  test "direction errors default to the one-way cause" do
    assert %TransportDirectionError{direction: :in, cause: :one_way} =
             TransportDirectionError.exception(direction: :in)

    assert %TransportDirectionError{message: "Outbound transport was split to another session"} =
             TransportDirectionError.exception(direction: :out, cause: :split)
  end

  defp establish do
    initiator = Decibel.new(@protocol, :ini, %{s: keypair()})
    responder = Decibel.new(@protocol, :rsp, %{s: keypair()})
    assert "" == Decibel.handshake_decrypt(responder, Decibel.handshake_encrypt(initiator))
    assert "" == Decibel.handshake_decrypt(initiator, Decibel.handshake_encrypt(responder))
    assert "" == Decibel.handshake_decrypt(responder, Decibel.handshake_encrypt(initiator))
    {initiator, responder}
  end

  defp exchange(initiator, responder, count) do
    for i <- 1..count do
      assert "#{i}" == Decibel.decrypt(responder, Decibel.encrypt(initiator, "#{i}"))
      assert "#{i}" == Decibel.decrypt(initiator, Decibel.encrypt(responder, "#{i}"))
    end
  end

  defp keypair, do: :crypto.generate_key(:ecdh, :x25519)

  defp run(holder, fun), do: GenServer.call(holder, {:run, fun})

  defp close_all(sessions), do: Enum.each(sessions, &Decibel.close/1)

  defp capture(call) do
    call.()
  rescue
    error -> error
  end

  defp assert_split_direction(call, direction) do
    error = assert_raise TransportDirectionError, call
    assert error.direction == direction
    assert error.cause == :split
  end

  defp assert_handoff_error(call, reason) do
    error = assert_raise HandoffError, call
    assert error.reason == reason
    error
  end

  defp assert_session_error(call, reason) do
    error = assert_raise SessionError, call
    assert error.reason == reason
    error
  end
end
