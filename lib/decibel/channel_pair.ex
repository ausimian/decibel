defmodule Decibel.ChannelPair do
  @moduledoc false
  alias Decibel.Cipher
  use TypedStruct

  alias Decibel.Cipher

  typedstruct do
    field(:h, binary())
    field(:in, Cipher.t())
    field(:out, Cipher.t())
  end

  @spec new(<<_::256>>, Decibel.Cipher.t(), Decibel.Cipher.t()) :: __MODULE__.t()
  def new(<<h::binary>>, %Cipher{} = cin, %Cipher{} = cout) do
    %__MODULE__{h: h, in: cin, out: cout}
  end

  @spec write_message(__MODULE__.t(), iodata(), iodata()) :: {__MODULE__.t(), iodata()}
  def write_message(%__MODULE__{out: cout} = state, ad, plaintext) do
    {updated, ciphertext} = Cipher.encrypt_with_aad(cout, ad, plaintext)
    {%__MODULE__{state | out: updated}, ciphertext}
  end

  @spec read_message(__MODULE__.t(), iodata(), iodata()) :: {__MODULE__.t(), iodata()}
  def read_message(%__MODULE__{in: cin} = state, ad, ciphertext) do
    {updated, plaintext} = Cipher.decrypt_with_aad(cin, ad, ciphertext)
    {%__MODULE__{state | in: updated}, plaintext}
  end

  @spec get_hash(__MODULE__.t()) :: binary()
  def get_hash(%__MODULE__{h: h}), do: h

  @spec rekey(__MODULE__.t(), :in | :out) :: __MODULE__.t()
  def rekey(%__MODULE__{in: cin} = state, :in) do
    %__MODULE__{state | in: Cipher.rekey(cin)}
  end

  def rekey(%__MODULE__{out: cout} = state, :out) do
    %__MODULE__{state | out: Cipher.rekey(cout)}
  end
end
