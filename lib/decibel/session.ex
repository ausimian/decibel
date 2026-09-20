defmodule Decibel.Session do
  @moduledoc """
  An opaque, process-owned Decibel session handle.

  Session handles may only be used by the process that created them and cannot
  be transferred. Calls from another process raise `Decibel.SessionError` with
  `reason: :not_owner`, even after the owner closes the session. Session state
  lives until `Decibel.close/1` is called, the owner process exits, or the
  `:decibel` OTP application stops. The owner's operations on a closed handle
  use `reason: :closed` while that application lifetime continues.

  Stopping the application invalidates every session immediately. Owner-local
  state from the inactive application generation is erased when that owner next
  calls Decibel or when the owner process exits, because a process dictionary
  cannot be modified by another process.

  Their fields are private implementation details and must not be inspected or
  constructed by callers. See `Decibel`'s **Ownership and lifetime** section for
  the complete concurrency, supervision, phase, and lifecycle contract.
  """

  alias Decibel.{ChannelPair, Handshake, SessionError, SessionKeys}

  @missing :missing
  @status_closed 1

  @enforce_keys [:owner, :id, :status, :generation, :proof]
  defstruct [:owner, :id, :status, :generation, :proof]

  @opaque t :: %__MODULE__{
            owner: pid(),
            id: reference(),
            status: reference(),
            generation: reference(),
            proof: binary()
          }

  @type phase :: SessionError.phase()
  @typep state :: Handshake.t() | ChannelPair.t()

  @doc false
  @spec create(state()) :: t()
  def create(state) do
    purge_inactive_sessions()
    owner = self()
    {id, status, generation, proof} = SessionKeys.issue()

    session = %__MODULE__{
      owner: owner,
      id: id,
      status: status,
      generation: generation,
      proof: proof
    }

    Process.put(storage_key(session), {status, generation, proof, state})
    session
  end

  @doc false
  @spec fetch!(term(), atom(), phase() | :any) :: state()
  def fetch!(session, operation, expected_phase) do
    session
    |> validate_handle!()
    |> fetch_state!()
    |> validate_phase!(operation, expected_phase)
  end

  @doc false
  @spec store!(t(), state()) :: state()
  def store!(
        %__MODULE__{
          owner: owner,
          status: status,
          generation: generation,
          proof: proof
        } = session,
        state
      )
      when owner == self() do
    if SessionKeys.active_generation?(generation) do
      Process.put(storage_key(session), {status, generation, proof, state})
      state
    else
      purge_generation(generation)
      raise SessionError, reason: :unknown
    end
  end

  @doc false
  @spec close!(term()) :: :ok
  def close!(session) do
    validated = validate_handle!(session)
    _state = validated |> fetch_state!() |> validate_phase!(:close, :any)
    Process.delete(storage_key(validated))
    :atomics.put(validated.status, 1, @status_closed)
    :ok
  end

  defp validate_handle!(
         %__MODULE__{
           owner: owner,
           id: id,
           status: status,
           generation: generation,
           proof: proof
         } = session
       )
       when is_pid(owner) and is_reference(id) and is_reference(status) and
              is_reference(generation) and is_binary(proof) do
    if owner == self() do
      validate_owned_handle!(session)
    else
      validate_foreign_handle!(session)
    end
  end

  defp validate_handle!(_session), do: raise(SessionError, reason: :unknown)

  defp validate_owned_handle!(session) do
    case Process.get(storage_key(session), @missing) do
      @missing ->
        if issued?(session), do: session, else: raise(SessionError, reason: :unknown)

      entry ->
        validate_owned_entry!(session, entry)
    end
  end

  defp validate_owned_entry!(session, {status, generation, proof, %Handshake{}}),
    do: validate_owned_entry_values!(session, status, generation, proof)

  defp validate_owned_entry!(session, {status, generation, proof, %ChannelPair{}}),
    do: validate_owned_entry_values!(session, status, generation, proof)

  defp validate_owned_entry!(_session, _entry), do: raise(SessionError, reason: :unknown)

  defp validate_owned_entry_values!(session, status, generation, proof) do
    if status == session.status and generation == session.generation and proof == session.proof do
      validate_active_generation!(session, generation)
    else
      raise SessionError, reason: :unknown
    end
  end

  defp validate_active_generation!(session, generation) do
    if SessionKeys.active_generation?(generation) do
      session
    else
      purge_generation(generation)
      raise SessionError, reason: :unknown
    end
  end

  defp purge_inactive_sessions do
    Enum.each(Process.get(), fn
      {{__MODULE__, _id} = key, {_status, generation, _proof, state}}
      when is_reference(generation) ->
        if session_state?(state) and not SessionKeys.active_generation?(generation) do
          Process.delete(key)
        end

      _other ->
        :ok
    end)
  end

  defp purge_generation(generation) do
    Enum.each(Process.get(), fn
      {{__MODULE__, _id} = key, {_status, ^generation, _proof, state}} ->
        if session_state?(state), do: Process.delete(key)

      _other ->
        :ok
    end)
  end

  defp session_state?(%Handshake{}), do: true
  defp session_state?(%ChannelPair{}), do: true
  defp session_state?(_state), do: false

  defp validate_foreign_handle!(session) do
    if issued?(session) do
      raise SessionError, reason: :not_owner
    else
      raise SessionError, reason: :unknown
    end
  end

  defp issued?(session),
    do:
      SessionKeys.issued?(
        session.owner,
        session.id,
        session.status,
        session.generation,
        session.proof
      )

  defp fetch_state!(session) do
    case Process.get(storage_key(session), @missing) do
      @missing ->
        raise_missing_state!(session)

      {status, generation, proof, state}
      when status == session.status and generation == session.generation and
             proof == session.proof ->
        state
    end
  end

  defp raise_missing_state!(session) do
    if :atomics.get(session.status, 1) == @status_closed do
      raise SessionError, reason: :closed
    else
      raise SessionError, reason: :unknown
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
