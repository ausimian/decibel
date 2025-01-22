defmodule Decibel.Symmetric do
  @moduledoc false
  use TypedStruct

  alias Decibel.{Cipher, Crypto, ChannelPair}

  typedstruct do
    field(:cs, Cipher.t())
    field(:hf, Crypto.hash())
    field(:ck, binary())
    field(:h, binary())
  end

  @doc false
  @spec initialize(Crypto.cipher(), Crypto.hash(), binary()) :: __MODULE__.t()
  def initialize(cf, hf, <<protocol_name::binary>>)
      when cf in [:chacha20_poly1305, :aes_256_gcm] and hf in [:sha256, :sha512, :blake2s, :blake2b] do
    hlen = Crypto.hash_len(hf)

    hash =
      if byte_size(protocol_name) <= hlen do
        String.pad_trailing(protocol_name, hlen, <<?\0>>)
      else
        Crypto.hash(hf, protocol_name)
      end

    %__MODULE__{cs: Cipher.new(cf), hf: hf, ck: hash, h: hash}
  end

  @doc false
  @spec mix_key(__MODULE__.t(), iodata()) :: __MODULE__.t()
  def mix_key(%__MODULE__{cs: cs, hf: hf, ck: ck} = sym, ikm) do
    {ck, <<tk::32-bytes, _::binary>>} = Crypto.hkdf(hf, ck, ikm, 2)
    %__MODULE__{sym | ck: ck, cs: Cipher.initialize_key(cs, tk)}
  end

  @doc false
  @spec mix_hash(__MODULE__.t(), iodata()) :: __MODULE__.t()
  def mix_hash(%__MODULE__{hf: hf, h: h} = sym, data) do
    %__MODULE__{sym | h: mix_hash(hf, h, data)}
  end

  @doc false
  @spec mix_key_and_hash(__MODULE__.t(), iodata()) :: __MODULE__.t()
  def mix_key_and_hash(%__MODULE__{cs: cs, hf: hf, ck: ck, h: h} = sym, ikm) do
    {ck, th, <<tk::32-bytes, _::binary>>} = Crypto.hkdf(hf, ck, ikm, 3)
    %__MODULE__{sym | ck: ck, h: mix_hash(hf, h, th), cs: Cipher.initialize_key(cs, tk)}
  end

  @doc false
  @spec get_hash(__MODULE__.t()) :: binary()
  def get_hash(%__MODULE__{h: h}), do: h

  @doc false
  @spec encrypt_and_hash(__MODULE__.t(), iodata()) :: {__MODULE__.t(), iodata()}
  def encrypt_and_hash(%__MODULE__{cs: cs, hf: hf, h: h} = sym, plaintext) do
    {cs, ciphertext} = Cipher.encrypt_with_aad(cs, h, plaintext)
    {%__MODULE__{sym | h: mix_hash(hf, h, ciphertext), cs: cs}, ciphertext}
  end

  @doc false
  @spec decrypt_and_hash(__MODULE__.t(), iodata()) :: {__MODULE__.t(), iodata()}
  def decrypt_and_hash(%__MODULE__{cs: cs, hf: hf, h: h} = sym, ciphertext) do
    {cs, plaintext} = Cipher.decrypt_with_aad(cs, h, ciphertext)
    {%__MODULE__{sym | h: mix_hash(hf, h, ciphertext), cs: cs}, plaintext}
  end

  @spec split(__MODULE__.t(), boolean(), binary()) :: ChannelPair.t()
  def split(%__MODULE__{cs: cs, ck: ck, hf: hf, h: h}, swap, rs) do
    {<<k1::32-bytes, _::binary>>, <<k2::32-bytes, _::binary>>} = Crypto.hkdf(hf, ck, <<>>, 2)
    cout = Cipher.initialize_key(cs, k1)
    cin = Cipher.initialize_key(cs, k2)

    if swap do
      ChannelPair.new(h, cin, cout, rs)
    else
      ChannelPair.new(h, cout, cin, rs)
    end
  end

  defp mix_hash(hf, h, data), do: Crypto.hash(hf, [h, data])
end
