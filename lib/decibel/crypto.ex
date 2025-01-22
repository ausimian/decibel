defmodule Decibel.Crypto do
  @moduledoc false

  @type cipher() :: :chacha20_poly1305 | :aes_256_gcm
  @type hash() :: :sha256 | :sha512 | :blake2s | :blake2b
  @type curve() :: :x25519 | :x448
  @type public_key() :: :crypto.dh_public()
  @type private_key() :: :crypto.dh_private()

  @rekey 2 ** 64 - 1

  @doc """
  Performs a Diffie-Hellman calculation between the private key of `keypair`
  and the public key and returns an output sequence of bytes of length
  [dh_len(f)](`dh_len/1`).
  """
  @spec dh(curve(), {public_key(), private_key()}, public_key()) :: binary()
  def dh(f, {_, private} = _keypair, public) when f in [:x25519, :x448] do
    :crypto.compute_key(:ecdh, public, private, f)
  end

  @doc """
  Returns the length, in bytes, of computed keys for a given curve.
  - `x25519` computed keys are 32 bytes
  - `x448` computed keys are 56 bytes
  """
  @spec dh_len(curve()) :: 32 | 56
  def dh_len(f) do
    case f do
      :x25519 -> 32
      :x448 -> 56
    end
  end

  @doc """
  Generates a new Diffie-Hellman key pair. A DH key pair consists of public
  key and private key elements. A public key represents an encoding of a DH
  public key into a byte sequence of length [dh_len(f)](`dh_len/1`).
  """
  @spec generate_keypair(curve()) :: {public_key(), private_key()}
  def generate_keypair(f) when f in [:x25519, :x448] do
    :crypto.generate_key(:ecdh, f)
  end

  @doc """
  Encrypts a plaintext.

  Encrypts plaintext using the cipher key of 32 bytes and an 8-byte
  unsigned integer nonce which must be unique for the key k. Encryption is
  done with an `AEAD` encryption mode with the associated data `aad` and
  returns a ciphertext that is the same size as the plaintext plus 16 bytes
  for authentication data.
  """
  @spec encrypt(cipher(), <<_::256>>, non_neg_integer(), iodata(), iodata()) :: iolist()
  def encrypt(cipher, <<key::binary-size(32)>>, nonce, aad, plaintext) do
    iv = cipher_iv(cipher, nonce)

    with {crypttext, tag} <- :crypto.crypto_one_time_aead(cipher, key, iv, plaintext, aad, true) do
      [crypttext, tag]
    end
  end

  @doc """
  Decrypts a plaintext.

  Decrypts ciphertext using a cipher key of 32 bytes, an 8-byte unsigned
  integer nonce, and associated data aad. Returns the plaintext, unless
  authentication fails, in which case an error is signaled to the caller.
  """
  @spec decrypt(cipher(), <<_::256>>, non_neg_integer(), iodata(), iodata()) :: binary() | :error
  def decrypt(cipher, <<key::binary-size(32)>>, nonce, aad, crypttext) do
    bytes = IO.iodata_to_binary(crypttext)
    {data, tag} = :erlang.split_binary(bytes, byte_size(bytes) - 16)
    :crypto.crypto_one_time_aead(cipher, key, cipher_iv(cipher, nonce), data, aad, tag, false)
  end

  @doc """
  Returns a new 32-byte cipher key as a pseudorandom function of `key`
  """
  @spec rekey(cipher(), <<_::256>>) :: <<_::256>>
  def rekey(cipher, <<key::binary-size(32)>>) do
    with [rekeyed, _] <- encrypt(cipher, key, @rekey, <<>>, <<0::256>>) do
      rekeyed
    end
  end

  @doc """
  Hash the specified data.

  Hashes some arbitrary-length data with a collision-resistant cryptographic
  hash function and returns an output of [hash_len(f)](`hash_len/1`) bytes.
  """
  @spec hash(hash(), iodata()) :: binary()
  def hash(f, data) when f in [:sha256, :sha512, :blake2s, :blake2b], do: :crypto.hash(f, data)

  @doc """
  Returns the output size, in bytes, of the specificied hash.
  """
  @spec hash_len(hash()) :: 32 | 64
  def hash_len(f) do
    case f do
      :sha256 -> 32
      :sha512 -> 64
      :blake2s -> 32
      :blake2b -> 64
    end
  end

  @doc """
  HMAC-based key derivation function.any()

  Takes a chaining key byte sequence of [hash_len(f)](`hash_len/1`) bytes,
  and an input key material byte sequence. Returns a pair or triple of byte
  sequences each of length [hash_len(f)](`hash_len/1`), depending on
  whether num_outputs is two or three.
  """
  @spec hkdf(hash(), iodata(), iodata(), 2 | 3) :: {binary(), binary()} | {binary(), binary(), binary()}
  def hkdf(f, chaining_key, input_key_material, num_outputs) when f in [:sha256, :sha512, :blake2s, :blake2b] do
    tk = hmac_hash(f, chaining_key, input_key_material)
    o1 = hmac_hash(f, tk, <<1>>)
    o2 = hmac_hash(f, tk, [o1, <<2>>])

    case num_outputs do
      2 -> {o1, o2}
      3 -> {o1, o2, hmac_hash(f, tk, [o2, <<3>>])}
    end
  end

  @spec hmac_hash(hash(), iodata(), iodata()) :: binary()
  defp hmac_hash(f, key, data) do
    :crypto.mac(:hmac, f, key, data)
  end

  defp cipher_iv(cipher, nonce) when is_integer(nonce) and nonce >= 0 and nonce <= @rekey do
    case cipher do
      :chacha20_poly1305 ->
        <<0::32, nonce::64-little>>

      :aes_256_gcm ->
        <<0::32, nonce::64-big>>
    end
  end
end
