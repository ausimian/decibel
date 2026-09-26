defmodule Decibel.Session do
  @moduledoc """
  An opaque, process-owned Decibel session handle.

  Session handles may only be used by their owner process. An in-progress
  handshake may be transferred once with `Decibel.handoff/2` and
  `Decibel.accept_handoff/1`; acceptance creates a new handle for the target.
  Calls from another process raise `Decibel.SessionError` with
  `reason: :not_owner`, even after the owner closes the session or exits.
  Session state lives until `Decibel.close/1` is called or the owner process
  exits, and the owner's operations on a closed handle use `reason: :closed`.

  Their fields are private implementation details and must not be inspected,
  altered, or constructed by callers. See `Decibel`'s **Ownership and
  lifetime** section for the complete concurrency, supervision, phase, and
  lifecycle contract.
  """

  alias Decibel.{ChannelPair, Handshake, SessionError}

  @missing :missing
  @accepted :accepted
  @sequence_key {__MODULE__, :sequence}

  @enforce_keys [:owner, :id, :seq]
  defstruct [:owner, :id, :seq]

  @opaque t :: %__MODULE__{owner: pid(), id: reference(), seq: non_neg_integer()}

  @type phase :: SessionError.phase()
  @typep state :: Handshake.t() | ChannelPair.t()
  @typep slot :: {key :: {module(), reference()}, accepted? :: boolean()}

  @doc false
  @spec create(state()) :: t()
  def create(state) do
    create_entry(state)
  end

  @doc false
  @spec create_accepted(Handshake.t()) :: t()
  def create_accepted(state) do
    create_entry({@accepted, state})
  end

  defp create_entry(entry) do
    session = %__MODULE__{owner: self(), id: make_ref(), seq: next_sequence()}
    Process.put(storage_key(session), entry)
    session
  end

  # Closing deletes a session's entry, so a missing entry alone cannot tell a
  # closed handle from one Decibel never issued. Each handle therefore carries
  # its owner's issue sequence number, and the owner keeps one counter of
  # handles issued so far. Storage stays keyed by the unique reference, so a
  # lost or reset counter can only change the reported reason; it can never
  # let one handle reach another session's state.
  defp next_sequence do
    sequence = issued_count()
    Process.put(@sequence_key, sequence + 1)
    sequence
  end

  defp issued_count do
    case Process.get(@sequence_key) do
      count when is_integer(count) and count >= 0 -> count
      _missing_or_invalid -> 0
    end
  end

  # Each operation reads its session's storage once. fetch!/3 returns a slot
  # holding the storage key and whether the entry records an accepted handoff,
  # and store!/2 writes the new state back through that slot without reading
  # the entry again. Nothing else touches the entry between the two calls,
  # because an operation runs serially in the owner process.
  @doc false
  @spec fetch!(term(), atom(), phase() | :any) :: {slot(), state()}
  def fetch!(session, operation, expected_phase) do
    validated = validate_handle!(session)
    key = storage_key(validated)
    {accepted?, state} = fetch_entry!(validated, key)
    {{key, accepted?}, validate_phase!(state, operation, expected_phase)}
  end

  @doc false
  @spec store!(slot(), state()) :: state()
  def store!({key, accepted?}, state) do
    Process.put(key, if(accepted?, do: {@accepted, state}, else: state))
    state
  end

  @doc false
  @spec close!(term()) :: :ok
  def close!(session) do
    {{key, _accepted?}, _state} = fetch!(session, :close, :any)
    Process.delete(key)
    :ok
  end

  @doc false
  @spec handoff!(term(), pid()) :: Decibel.Handoff.t()
  def handoff!(session, target) do
    {{key, accepted?}, state} = fetch!(session, :handoff, :any)

    if accepted? do
      raise SessionError, reason: :already_handed_off
    end

    validate_phase!(state, :handoff, :handshake)
    Decibel.Handoff.validate_target!(target)
    ticket = Decibel.Handoff.create(state, target)
    Process.delete(key)
    ticket
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

  defp fetch_entry!(session, key) do
    case Process.get(key, @missing) do
      @missing -> raise SessionError, reason: missing_reason(session)
      %Handshake{} = state -> {false, state}
      %ChannelPair{} = state -> {false, state}
      {@accepted, %Handshake{} = state} -> {true, state}
      {@accepted, %ChannelPair{} = state} -> {true, state}
      _invalid_state -> raise SessionError, reason: :unknown
    end
  end

  # An owner-local handle with no entry was closed if its owner issued it.
  defp missing_reason(%__MODULE__{seq: sequence}) when is_integer(sequence) and sequence >= 0 do
    if sequence < issued_count(), do: :closed, else: :unknown
  end

  defp missing_reason(_session), do: :unknown

  defp validate_phase!(state, _operation, :any), do: state

  defp validate_phase!(%Handshake{} = state, _operation, :handshake), do: state

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
