defmodule Decibel.HandoffTest do
  use ExUnit.Case

  alias Decibel.{HandoffError, SessionError}

  @protocol "Noise_IK_25519_ChaChaPoly_BLAKE2s"

  defmodule Peer do
    use GenServer

    def start_link, do: GenServer.start_link(__MODULE__, nil)

    @impl true
    def init(_argument), do: {:ok, nil}

    @impl true
    def handle_call({:accept, ticket}, _from, nil) do
      session = Decibel.accept_handoff(ticket)
      {:reply, {:ok, session, Decibel.remote_key(session)}, session}
    end

    def handle_call({:accept_again, ticket}, _from, session) do
      error =
        try do
          Decibel.accept_handoff(ticket)
        rescue
          error in HandoffError -> error
        end

      {:reply, error, session}
    end

    def handle_call({:handoff_again, target}, _from, session) do
      error =
        try do
          Decibel.handoff(session, target)
        rescue
          error in SessionError -> error
        end

      {:reply, error, session}
    end

    def handle_call(:respond, _from, session) do
      message = Decibel.handshake_encrypt(session)
      {:reply, {message, Decibel.handshake_complete?(session)}, session}
    end

    def handle_call({:decrypt, ciphertext}, _from, session) do
      {:reply, Decibel.decrypt(session, ciphertext), session}
    end
  end

  test "the target continues the same authenticated handshake and owns transport" do
    {initiator, responder, initiator_public} = begin_handshake()
    {:ok, peer} = Peer.start_link()

    ticket = Decibel.handoff(responder, peer)
    assert inspect(ticket) == "#Decibel.Handoff<opaque>"
    assert Map.keys(ticket) |> Enum.sort() == [:__struct__, :secret, :server]

    assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :not_target)
    assert_session_error(fn -> Decibel.handshake_encrypt(responder) end, :closed)
    assert_session_error(fn -> Decibel.remote_key(responder) end, :closed)

    assert {:ok, target_session, ^initiator_public} = GenServer.call(peer, {:accept, ticket})
    assert target_session.owner == peer
    assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :unavailable)
    assert %HandoffError{reason: :unavailable} = GenServer.call(peer, {:accept_again, ticket})

    assert %SessionError{reason: :already_handed_off} =
             GenServer.call(peer, {:handoff_again, self()})

    {response, true} = GenServer.call(peer, :respond)
    assert "" == Decibel.handshake_decrypt(initiator, response)
    assert Decibel.handshake_complete?(initiator)

    assert %SessionError{reason: :already_handed_off} =
             GenServer.call(peer, {:handoff_again, self()})

    ciphertext = Decibel.encrypt(initiator, "after handoff")
    assert "after handoff" == GenServer.call(peer, {:decrypt, ciphertext})

    Decibel.close(initiator)
    GenServer.stop(peer)
  end

  test "invalid owner, phase, and target leave the live session untouched" do
    {initiator, responder, _initiator_public} = begin_handshake()

    task = Task.async(fn -> capture_session_error(fn -> Decibel.handoff(responder, self()) end) end)
    assert %SessionError{reason: :not_owner} = Task.await(task)

    assert_handoff_error(fn -> Decibel.handoff(responder, :not_a_pid) end, :invalid_target)
    dead = spawn(fn -> :ok end)
    monitor = Process.monitor(dead)
    assert_receive {:DOWN, ^monitor, :process, ^dead, _reason}
    assert_handoff_error(fn -> Decibel.handoff(responder, dead) end, :invalid_target)

    assert Decibel.remote_key(responder) != nil
    response = Decibel.handshake_encrypt(responder)
    assert "" == Decibel.handshake_decrypt(initiator, response)
    assert_session_error(fn -> Decibel.handoff(responder, self()) end, :wrong_phase)

    Decibel.close(initiator)
    Decibel.close(responder)
  end

  test "target exit and ticket expiry discard unclaimed handshakes" do
    for fate <- [:target_exit, :expiry] do
      {initiator, responder, _initiator_public} = begin_handshake()
      target = spawn(fn -> receive do: (:stop -> :ok) end)
      ticket = Decibel.handoff(responder, target)
      monitor = Process.monitor(ticket.server)

      case fate do
        :target_exit ->
          send(target, :stop)

        :expiry ->
          send(ticket.server, :expire)
          send(ticket.server, {:timeout, make_ref(), :expire})
          %{timer: timer} = :sys.get_state(ticket.server)
          assert Process.alive?(ticket.server)
          send(ticket.server, {:timeout, timer, :expire})
      end

      assert_receive {:DOWN, ^monitor, :process, _server, :normal}
      assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :unavailable)
      assert_session_error(fn -> Decibel.close(responder) end, :closed)

      if fate == :expiry, do: send(target, :stop)
      Decibel.close(initiator)
    end
  end

  test "malformed tickets have a stable error" do
    for ticket <- [nil, make_ref(), %Decibel.Handoff{server: self(), secret: :invalid}] do
      assert_handoff_error(fn -> Decibel.accept_handoff(ticket) end, :invalid_ticket)
    end

    for response <- [:ok, {:ok, :not_a_handshake}, {:error, :not_a_handoff_reason}] do
      server =
        spawn(fn ->
          receive do
            {:"$gen_call", from, _request} -> GenServer.reply(from, response)
          end
        end)

      forged = %Decibel.Handoff{server: server, secret: make_ref()}
      assert_handoff_error(fn -> Decibel.accept_handoff(forged) end, :invalid_ticket)
    end
  end

  test "unexpected ticket messages do not discard state or expose it in status" do
    {initiator, responder, initiator_public} = begin_handshake()
    {:ok, peer} = Peer.start_link()
    ticket = Decibel.handoff(responder, peer)

    assert {:error, :invalid_ticket} == GenServer.call(ticket.server, :unexpected)
    GenServer.cast(ticket.server, :unexpected)
    assert inspect(:sys.get_status(ticket.server)) =~ "redacted"
    refute inspect(:sys.get_status(ticket.server)) =~ "Decibel.Handshake"

    assert {:ok, _session, ^initiator_public} = GenServer.call(peer, {:accept, ticket})

    Decibel.close(initiator)
    GenServer.stop(peer)
  end

  defp begin_handshake do
    {initiator_public, _private} = initiator_static = :crypto.generate_key(:ecdh, :x25519)
    {responder_public, _private} = responder_static = :crypto.generate_key(:ecdh, :x25519)
    initiator = Decibel.new(@protocol, :ini, %{s: initiator_static, rs: responder_public})
    responder = Decibel.new(@protocol, :rsp, %{s: responder_static})

    message = Decibel.handshake_encrypt(initiator)
    assert "" == Decibel.handshake_decrypt(responder, message)
    assert Decibel.remote_key(responder) == initiator_public

    {initiator, responder, initiator_public}
  end

  defp assert_handoff_error(call, reason) do
    error = assert_raise HandoffError, call
    assert error.reason == reason
    refute error.message =~ "#PID"
    refute error.message =~ "#Reference"
    error
  end

  defp assert_session_error(call, reason) do
    error = assert_raise SessionError, call
    assert error.reason == reason
    error
  end

  defp capture_session_error(call) do
    call.()
  rescue
    error in SessionError -> error
  end
end
