defmodule Decibel.SessionError do
  @moduledoc """
  Raised when a session handle cannot be used for an operation.

  The `:reason` field is the stable machine-readable failure contract:

  - `:not_owner` means a structurally valid session handle was used outside the
    process named by its owner PID, whether the session is live, closed, or its
    owner has exited. Its exact message is
    `"Session is owned by another process"`.
  - `:closed` means the owner tried to use a session it has already closed. Its
    exact message is `"Session is closed"`.
  - `:unknown` means the value is not a known owner-local session handle.
    Legacy bare references from Decibel 0.2, malformed values, and well-shaped
    owner-local handles without stored state use this reason. Its exact message
    is `"Unknown Decibel session"`.
  - `:wrong_phase` means the session is live, but the operation is not valid for
    the current handshake turn or transport phase. Its exact message is
    `"Session operation <operation> requires <expected_phase> phase; current
    phase is <actual_phase>"`, with the bracketed values replaced by the
    corresponding atoms.

  Validation first checks the handle shape, then compares its owner PID with
  the calling process, then performs the owner-local state lookup, and finally
  validates the phase. Consequently, a structurally valid handle used from
  another process reports `:not_owner` before Decibel considers whether owner-
  local state exists or was closed. This includes a handle retained after its
  owner exits and a genuine-looking foreign handle.

  This owner-PID-only classification is deliberate. Session handles are opaque
  and must not be constructed or altered by callers. Decibel intentionally has
  no handle registry, issuance proof, signature, or global verification state.

  For `:wrong_phase`, `:operation`, `:expected_phase`, and `:actual_phase`
  identify the rejected transition. Those fields are `nil` for all other
  reasons.
  """

  @typedoc "The phase or handshake turn of a live session."
  @type phase :: :handshake_write | :handshake_read | :transport

  @typedoc "The reason a session operation was rejected."
  @type reason :: :not_owner | :closed | :unknown | :wrong_phase

  defexception [:reason, :operation, :expected_phase, :actual_phase, :message]

  @type t :: %__MODULE__{
          reason: reason(),
          operation: atom() | nil,
          expected_phase: phase() | nil,
          actual_phase: phase() | nil,
          message: String.t()
        }

  @impl true
  def exception(options) do
    reason = Keyword.fetch!(options, :reason)
    operation = Keyword.get(options, :operation)
    expected_phase = Keyword.get(options, :expected_phase)
    actual_phase = Keyword.get(options, :actual_phase)

    message = message(reason, operation, expected_phase, actual_phase)

    %__MODULE__{
      reason: reason,
      operation: operation,
      expected_phase: expected_phase,
      actual_phase: actual_phase,
      message: message
    }
  end

  defp message(:not_owner, nil, nil, nil), do: "Session is owned by another process"
  defp message(:closed, nil, nil, nil), do: "Session is closed"
  defp message(:unknown, nil, nil, nil), do: "Unknown Decibel session"

  defp message(:wrong_phase, operation, expected_phase, actual_phase) do
    "Session operation #{operation} requires #{expected_phase} phase; " <>
      "current phase is #{actual_phase}"
  end
end
