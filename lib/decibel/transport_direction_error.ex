defmodule Decibel.TransportDirectionError do
  @moduledoc """
  Raised when an operation targets a transport direction the session does not
  hold.

  The `:direction` field is `:in` for inbound transport or `:out` for outbound
  transport.

  The `:cause` field is stable:

  - `:one_way`: the session's one-way handshake does not permit the direction.
  - `:split`: the direction was moved to another session by `Decibel.split/3`.
  """

  defexception [:direction, :cause, :message]

  @type cause :: :one_way | :split

  @type t :: %__MODULE__{direction: :in | :out, cause: cause(), message: String.t()}

  @impl true
  def exception(options) do
    direction = Keyword.fetch!(options, :direction)
    cause = Keyword.get(options, :cause, :one_way)
    %__MODULE__{direction: direction, cause: cause, message: message(direction, cause)}
  end

  defp message(:in, :one_way), do: "Inbound transport is not permitted by this one-way handshake"
  defp message(:out, :one_way), do: "Outbound transport is not permitted by this one-way handshake"
  defp message(:in, :split), do: "Inbound transport was split to another session"
  defp message(:out, :split), do: "Outbound transport was split to another session"
end
