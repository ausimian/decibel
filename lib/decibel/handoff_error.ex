defmodule Decibel.HandoffError do
  @moduledoc """
  Raised when a handshake handoff cannot be created or accepted.

  The `:reason` field is stable:

  - `:invalid_target`: the destination is not a live local process.
  - `:invalid_ticket`: the value is not a valid handoff ticket.
  - `:not_target`: a valid ticket was accepted outside its designated process.
  - `:unavailable`: the ticket was already claimed, expired, or discarded when
    its target exited.
  - `:timeout`: the ticket process did not respond before the acceptance deadline.

  Errors contain no handshake state or key material.
  """

  @type reason :: :invalid_target | :invalid_ticket | :not_target | :unavailable | :timeout

  defexception [:reason, :message]

  @type t :: %__MODULE__{reason: reason(), message: String.t()}

  @impl true
  def exception(options) do
    reason = Keyword.fetch!(options, :reason)
    %__MODULE__{reason: reason, message: reason_message(reason)}
  end

  defp reason_message(:invalid_target), do: "Handoff target must be a live local process"
  defp reason_message(:invalid_ticket), do: "Invalid Decibel handoff ticket"
  defp reason_message(:not_target), do: "Handoff ticket belongs to another process"
  defp reason_message(:unavailable), do: "Handoff ticket is unavailable"
  defp reason_message(:timeout), do: "Handoff ticket acceptance timed out"
end
