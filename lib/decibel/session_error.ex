defmodule Decibel.SessionError do
  @moduledoc """
  Raised when a session handle cannot be used for an operation.

  The `:reason` field is the stable machine-readable failure contract:

  - `:not_owner` means a genuine session handle was used outside the process
    that created it, whether the session is live or closed.
  - `:closed` means the owner tried to use a session it has already closed.
  - `:unknown` means the value is not a known session handle. Legacy bare
    references from Decibel 0.2 and all other terms use this reason.
  - `:wrong_phase` means the session is live, but the operation is not valid for
    the current handshake turn or transport phase.

  A genuine handle used in another process reports `:not_owner`, not
  `:unknown` or `:closed`, so ownership mistakes remain distinct from migration
  and lifecycle mistakes. For `:wrong_phase`, `:operation`, `:expected_phase`,
  and `:actual_phase` identify the rejected transition. Those fields are `nil`
  for all other reasons.
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

    message =
      message(reason, operation, expected_phase, actual_phase)

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
