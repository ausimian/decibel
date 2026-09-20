defmodule Decibel.DecryptionError do
  @moduledoc """
  Raised when a peer message cannot be decrypted or processed safely.

  The `:reason` field is the stable machine-readable failure contract:

  - `:truncated` means a required public-key field or authentication tag was
    incomplete.
  - `:authentication_failed` means AEAD verification rejected the ciphertext.
  - `:invalid_public_key` means the peer supplied a public key rejected by the
    selected DH function.

  All reasons use the message `"Decryption failed"` so backend details and peer
  data are not exposed.

  If the failure occurs during the handshake phase, the `:remote_keys`
  field contains any remote public keys processed before the failure. Failed
  operations leave the session state and cipher nonce unchanged.
  """

  @typedoc "The reason a peer message could not be processed."
  @type reason :: :truncated | :authentication_failed | :invalid_public_key

  @type t :: %__MODULE__{
          reason: reason(),
          remote_keys: [] | [re: binary() | nil, rs: binary() | nil],
          message: String.t()
        }

  defexception message: "Decryption failed", reason: :authentication_failed, remote_keys: []
end
