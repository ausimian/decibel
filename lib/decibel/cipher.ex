defmodule Decibel.Cipher do
  @moduledoc false
  use TypedStruct
  alias Decibel.Crypto

  @rekey 2 ** 64 - 1

  typedstruct do
    field(:type, Crypto.cipher())
    field(:k, nil | binary(), default: nil)
    field(:n, non_neg_integer(), default: 0)
  end

  @doc """
  Create a new cipher of the specified type.
  """
  @spec new(Crypto.cipher()) :: __MODULE__.t()
  def new(type) when type in [:chacha20_poly1305, :aes_256_gcm] do
    %__MODULE__{type: type}
  end

  @doc """
  Initialize the key of the cipher.
  """
  @spec initialize_key(__MODULE__.t(), <<_::256>>) :: __MODULE__.t()
  def initialize_key(%__MODULE__{} = cipher, <<k::binary-size(32)>>) do
    %__MODULE__{cipher | k: k, n: 0}
  end

  @doc """
  Rekey the cipher.
  """
  @spec rekey(__MODULE__.t()) :: __MODULE__.t()
  def rekey(%__MODULE__{type: type, k: <<k::binary-size(32)>>} = cipher) do
    %__MODULE__{cipher | k: Crypto.rekey(type, k)}
  end

  @doc """
  Set the nonce value of the cipher.
  """
  @spec set_nonce(__MODULE__.t(), non_neg_integer()) :: __MODULE__.t()
  def set_nonce(%__MODULE__{} = cipher, n) when is_integer(n) and n >= 0 and n < @rekey do
    %__MODULE__{cipher | n: n}
  end

  @doc """
  Encrypts the specified plaintext.

  Encrypts the specified `plaintext` using the cipher's key `k` of 32 bytes
  and the 8-byte unsigned integer nonce `n` which must be unique for the key `k`.
  Returns the ciphertext. Encryption is done with an _AEAD_ encryption mode
  with the associated data `aad` and returns an update cipher and a
  ciphertext that is the same size as the plaintext plus 16 bytes for
  authentication data.
  """
  @spec encrypt_with_aad(__MODULE__.t(), iodata(), iodata()) :: {__MODULE__.t(), iodata()}
  def encrypt_with_aad(%__MODULE__{k: nil} = cipher, _, plaintext), do: {cipher, plaintext}

  def encrypt_with_aad(%__MODULE__{type: type, k: k, n: n} = cipher, aad, plaintext)
      when is_integer(n) and n >= 0 and n < @rekey - 1 do
    {%__MODULE__{cipher | n: n + 1}, Crypto.encrypt(type, k, n, aad, plaintext)}
  end

  @doc """
  Decrypts the specified ciphertext.

  Decrypts `ciphertext` using the cipher's key `k` of 32 bytes, its 8-byte
  unsigned integer nonce `n`, and associated data `aad`. Returns the updated
  cipher and the plaintext, unless authentication fails, in which case an
  error is signaled to the caller.
  """
  @spec decrypt_with_aad(__MODULE__.t(), iodata(), iodata()) :: {__MODULE__.t(), iodata()} | :error
  def decrypt_with_aad(%__MODULE__{k: nil} = cipher, _, ciphertext), do: {cipher, ciphertext}

  def decrypt_with_aad(%__MODULE__{type: type, k: k, n: n} = cipher, aad, ciphertext)
      when is_integer(n) and n >= 0 and n < @rekey - 1 do
    case Crypto.decrypt(type, k, n, aad, ciphertext) do
      plaintext when is_binary(plaintext) ->
        {%__MODULE__{cipher | n: n + 1}, plaintext}

      :error ->
        raise "Decryption failed"
    end
  end
end
