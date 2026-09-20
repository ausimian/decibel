defmodule Decibel.TransportDirectionError do
  @moduledoc """
  Raised when an operation targets the discarded direction of a one-way
  transport.

  The `:direction` field is `:in` for inbound transport or `:out` for outbound
  transport.
  """

  defexception [:direction, :message]

  @type t :: %__MODULE__{direction: :in | :out, message: String.t()}

  @impl true
  def exception(direction: :in) do
    %__MODULE__{
      direction: :in,
      message: "Inbound transport is not permitted by this one-way handshake"
    }
  end

  def exception(direction: :out) do
    %__MODULE__{
      direction: :out,
      message: "Outbound transport is not permitted by this one-way handshake"
    }
  end
end
