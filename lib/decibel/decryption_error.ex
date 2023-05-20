defmodule Decibel.DecryptionError do
  @moduledoc """
  Represents a decryption failure.

  If the failure occurs during the handshake phase, the `:remote_keys`
  field will contain any remote public keys used in the handshake.
  """
  defexception message: "Decryption failed", remote_keys: []
end
