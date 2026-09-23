defmodule Decibel.Handoff do
  @moduledoc """
  An opaque, single-use ticket for transferring an in-progress handshake.

  A ticket contains no cryptographic state. The state is held by a short-lived
  process until its designated target accepts it, the target exits, or the
  ticket expires. Callers must not inspect, alter, or construct tickets.
  Processes on the same BEAM node are trusted; PID binding enforces the public
  ownership contract, not isolation from malicious local processes.
  """

  use GenServer

  alias Decibel.{HandoffError, Handshake}

  @lifetime_ms 60_000
  @accept_timeout_ms @lifetime_ms + 5_000

  @enforce_keys [:server, :secret]
  defstruct [:server, :secret]

  @opaque t :: %__MODULE__{server: pid(), secret: reference()}

  @doc false
  @spec validate_target!(term()) :: :ok
  def validate_target!(target) do
    if is_pid(target) and node(target) == node() and Process.alive?(target) do
      :ok
    else
      raise HandoffError, reason: :invalid_target
    end
  end

  @doc false
  @spec create(Decibel.Handshake.t(), pid()) :: t()
  def create(handshake, target) do
    secret = make_ref()
    {:ok, server} = GenServer.start(__MODULE__, {handshake, target, secret})
    %__MODULE__{server: server, secret: secret}
  end

  @doc false
  @spec accept!(term()) :: Decibel.Handshake.t()
  def accept!(%__MODULE__{server: server, secret: secret})
      when is_pid(server) and is_reference(secret) do
    result =
      try do
        GenServer.call(server, {:accept, secret}, @accept_timeout_ms)
      catch
        :exit, {:timeout, _call} -> {:error, :timeout}
        :exit, _reason -> {:error, :unavailable}
      end

    case result do
      {:ok, %Handshake{} = handshake} ->
        handshake

      {:error, reason} when reason in [:invalid_ticket, :not_target, :unavailable, :timeout] ->
        raise HandoffError, reason: reason

      _unexpected ->
        raise HandoffError, reason: :invalid_ticket
    end
  end

  def accept!(_ticket), do: raise(HandoffError, reason: :invalid_ticket)

  @impl true
  def init({handshake, target, secret}) do
    monitor = Process.monitor(target)
    timer = :erlang.start_timer(@lifetime_ms, self(), :expire)
    deadline = System.monotonic_time(:millisecond) + @lifetime_ms

    {:ok,
     %{
       handshake: handshake,
       target: target,
       secret: secret,
       monitor: monitor,
       timer: timer,
       deadline: deadline
     }}
  end

  @impl true
  def handle_call({:accept, secret}, {caller, _tag}, state) do
    cond do
      System.monotonic_time(:millisecond) >= state.deadline ->
        {:stop, :normal, {:error, :unavailable}, state}

      secret != state.secret ->
        {:reply, {:error, :invalid_ticket}, state}

      caller != state.target ->
        {:reply, {:error, :not_target}, state}

      true ->
        {:stop, :normal, {:ok, state.handshake}, state}
    end
  end

  def handle_call(_request, _from, state), do: {:reply, {:error, :invalid_ticket}, state}

  @impl true
  def handle_cast(_message, state), do: {:noreply, state}

  @impl true
  def handle_info({:timeout, timer, :expire}, %{timer: timer} = state) do
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, monitor, :process, target, _reason}, %{monitor: monitor, target: target} = state) do
    {:stop, :normal, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def format_status(status) do
    status
    |> Map.put(:state, :redacted)
    |> Map.put(:message, :redacted)
  end
end

defimpl Inspect, for: Decibel.Handoff do
  def inspect(_ticket, _options), do: "#Decibel.Handoff<opaque>"
end
