defmodule Decibel.NonceError do
  @moduledoc """
  Raised when a cipher nonce is exhausted or a caller supplies an invalid
  nonce.

  The `:reason` field distinguishes an exhausted CipherState from an
  out-of-range value. The `:nonce` field contains the offending value.
  """

  @typedoc "The reason a nonce operation failed."
  @type reason :: :exhausted | :out_of_range

  defexception [:reason, :nonce, :message]

  @type t :: %__MODULE__{
          reason: reason(),
          nonce: term(),
          message: String.t()
        }

  @impl true
  def exception(options) do
    reason = Keyword.fetch!(options, :reason)
    nonce = Keyword.fetch!(options, :nonce)

    message =
      case reason do
        :exhausted ->
          "Cipher nonce is exhausted"

        :out_of_range ->
          inspected = inspect(nonce, limit: 10, printable_limit: 50)
          "Nonce must be an integer from 0 to 18446744073709551614, got: #{inspected}"
      end

    %__MODULE__{reason: reason, nonce: nonce, message: message}
  end
end
