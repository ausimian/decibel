defmodule Decibel.NonceError do
  @moduledoc """
  Raised when a cipher nonce is exhausted, a caller supplies an invalid nonce,
  or an outbound nonce would move backwards.

  The `:reason` field distinguishes an exhausted CipherState, an out-of-range
  value, and an outbound rewind. The `:nonce` field contains the offending
  value. For a rewind, `:current_nonce` contains the unchanged outbound nonce;
  it is `nil` for other reasons.
  """

  @typedoc "The reason a nonce operation failed."
  @type reason :: :exhausted | :out_of_range | :rewind

  defexception [:reason, :nonce, :current_nonce, :message]

  @type t :: %__MODULE__{
          reason: reason(),
          nonce: term(),
          current_nonce: non_neg_integer() | nil,
          message: String.t()
        }

  @impl true
  def exception(options) do
    reason = Keyword.fetch!(options, :reason)
    nonce = Keyword.fetch!(options, :nonce)
    current_nonce = Keyword.get(options, :current_nonce)

    message =
      case reason do
        :exhausted ->
          "Cipher nonce is exhausted"

        :out_of_range ->
          inspected = inspect(nonce, limit: 10, printable_limit: 50)
          "Nonce must be an integer from 0 to 18446744073709551614, got: #{inspected}"

        :rewind ->
          "Outbound nonce cannot move backwards from #{current_nonce} to #{nonce}"
      end

    %__MODULE__{reason: reason, nonce: nonce, current_nonce: current_nonce, message: message}
  end
end
