defmodule Decibel.Session do
  @moduledoc """
  An opaque, process-owned Decibel session handle.

  Session handles may only be used by the process that created them and cannot
  be transferred. Calls from another process raise `Decibel.SessionError` with
  `reason: :not_owner`, even after the owner closes the session or exits.
  Session state lives until `Decibel.close/1` is called or the owner process
  exits, and the owner's operations on a closed handle use `reason: :closed`.

  Their fields are private implementation details and must not be inspected,
  altered, or constructed by callers. See `Decibel`'s **Ownership and
  lifetime** section for the complete concurrency, supervision, phase, and
  lifecycle contract.
  """

  alias Decibel.{ChannelPair, Handshake, SessionError}

  @closed :closed
  @missing :missing

  @enforce_keys [:owner, :id]
  defstruct [:owner, :id]

  @opaque t :: %__MODULE__{owner: pid(), id: reference()}

  @type phase :: SessionError.phase()
  @typep state :: Handshake.t() | ChannelPair.t()

  @doc false
  @spec create(state()) :: t()
  def create(state) do
    session = %__MODULE__{owner: self(), id: make_ref()}
    Process.put(storage_key(session), state)
    session
  end

  @doc false
  @spec fetch!(term(), atom(), phase() | :any) :: {t(), state()}
  def fetch!(session, operation, expected_phase) do
    validated = validate_handle!(session)

    state =
      validated
      |> fetch_state!()
      |> validate_phase!(operation, expected_phase)

    {validated, state}
  end

  @doc false
  @spec store!(t(), state()) :: state()
  def store!(%__MODULE__{owner: owner} = session, state) when owner == self() do
    Process.put(storage_key(session), state)
    state
  end

  @doc false
  @spec close!(term()) :: :ok
  def close!(session) do
    validated = validate_handle!(session)
    _state = validated |> fetch_state!() |> validate_phase!(:close, :any)
    Process.put(storage_key(validated), @closed)
    :ok
  end

  defp validate_handle!(%__MODULE__{owner: owner, id: id} = session)
       when is_pid(owner) and is_reference(id) do
    # Deliberate API decision: owner mismatch is classified from the handle's
    # owner PID alone. Handles are opaque and caller construction is unsupported;
    # no registry, issuance proof, signature, or global verification exists.
    if owner == self() do
      session
    else
      raise SessionError, reason: :not_owner
    end
  end

  defp validate_handle!(_session), do: raise(SessionError, reason: :unknown)

  defp fetch_state!(session) do
    case Process.get(storage_key(session), @missing) do
      @missing -> raise SessionError, reason: :unknown
      @closed -> raise SessionError, reason: :closed
      %Handshake{} = state -> state
      %ChannelPair{} = state -> state
      _invalid_state -> raise SessionError, reason: :unknown
    end
  end

  defp validate_phase!(state, _operation, :any), do: state

  defp validate_phase!(state, operation, expected_phase) do
    actual_phase = phase(state)

    if actual_phase == expected_phase do
      state
    else
      raise SessionError,
        reason: :wrong_phase,
        operation: operation,
        expected_phase: expected_phase,
        actual_phase: actual_phase
    end
  end

  defp phase(%ChannelPair{}), do: :transport

  defp phase(%Handshake{role: role, hs: [{next_role, _tokens} | _rest]}) do
    if role == next_role, do: :handshake_write, else: :handshake_read
  end

  defp storage_key(%__MODULE__{id: id}), do: {__MODULE__, id}
end

defimpl Inspect, for: Decibel.Session do
  import Inspect.Algebra

  def inspect(%Decibel.Session{owner: owner}, options) do
    concat(["#Decibel.Session<owner: ", to_doc(owner, options), ">"])
  end
end
