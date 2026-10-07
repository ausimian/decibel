defmodule Decibel.ChannelPair do
  @moduledoc false
  alias Decibel.{Cipher, NonceError, TransportDirectionError}
  use TypedStruct

  @typedoc "The kind of handshake that established a channel pair."
  @type handshake_mode :: :interactive | :one_way

  @typedoc "A handshake mode, or `:split` for one half of a split interactive pair."
  @type mode :: handshake_mode() | :split

  typedstruct do
    field(:h, Decibel.handshake_hash())
    field(:mode, mode())
    field(:in, Cipher.t() | nil)
    field(:out, Cipher.t() | nil)
    field(:rs, binary() | nil)
  end

  @spec new(Decibel.handshake_hash(), mode(), Cipher.t() | nil, Cipher.t() | nil, binary() | nil) ::
          __MODULE__.t()
  def new(<<h::binary>>, mode, cin, cout, rs) when mode in [:interactive, :one_way] do
    %__MODULE__{h: h, mode: mode, in: cin, out: cout, rs: rs}
  end

  # Splits an interactive pair into two halves that each hold one direction.
  # Returns the half that keeps the other direction first and the half holding
  # `direction` second. Each cipher ends up in exactly one half.
  @spec split(__MODULE__.t(), :in | :out) :: {kept :: __MODULE__.t(), moved :: __MODULE__.t()}
  def split(%__MODULE__{mode: :interactive} = state, :in) do
    {%__MODULE__{state | mode: :split, in: nil}, %__MODULE__{state | mode: :split, out: nil}}
  end

  def split(%__MODULE__{mode: :interactive} = state, :out) do
    {%__MODULE__{state | mode: :split, out: nil}, %__MODULE__{state | mode: :split, in: nil}}
  end

  def split(%__MODULE__{mode: :one_way}, _direction) do
    raise ArgumentError, "a one-way transport has only one direction and cannot be split"
  end

  def split(%__MODULE__{mode: :split}, _direction) do
    raise ArgumentError, "a split transport has only one direction and cannot be split again"
  end

  # Returns the nonce the message was encrypted under along with the ciphertext.
  @spec write_message(__MODULE__.t(), iodata(), iodata()) ::
          {__MODULE__.t(), Decibel.usable_nonce(), iodata()}
  def write_message(%__MODULE__{out: nil} = state, _ad, _plaintext), do: raise_direction_error(state, :out)

  def write_message(%__MODULE__{out: %Cipher{n: n} = cout} = state, ad, plaintext) do
    {updated, ciphertext} = Cipher.encrypt_with_aad(cout, ad, plaintext)
    {%__MODULE__{state | out: updated}, n, ciphertext}
  end

  @spec read_message(__MODULE__.t(), iodata(), iodata()) :: {__MODULE__.t(), iodata()}
  def read_message(%__MODULE__{in: nil} = state, _ad, _ciphertext), do: raise_direction_error(state, :in)

  def read_message(%__MODULE__{in: cin} = state, ad, ciphertext) do
    {updated, plaintext} = Cipher.decrypt_with_aad(cin, ad, ciphertext)
    {%__MODULE__{state | in: updated}, plaintext}
  end

  @spec get_hash(__MODULE__.t()) :: Decibel.handshake_hash()
  def get_hash(%__MODULE__{h: h}), do: h

  @spec rekey(__MODULE__.t(), :in | :out) :: __MODULE__.t()
  def rekey(%__MODULE__{in: nil} = state, :in), do: raise_direction_error(state, :in)

  def rekey(%__MODULE__{in: cin} = state, :in) do
    %__MODULE__{state | in: Cipher.rekey(cin)}
  end

  def rekey(%__MODULE__{out: nil} = state, :out), do: raise_direction_error(state, :out)

  def rekey(%__MODULE__{out: cout} = state, :out) do
    %__MODULE__{state | out: Cipher.rekey(cout)}
  end

  @spec get_n(__MODULE__.t(), :in | :out) :: Decibel.nonce()
  def get_n(%__MODULE__{in: nil} = state, :in), do: raise_direction_error(state, :in)
  def get_n(%__MODULE__{in: %Cipher{n: n}}, :in), do: n
  def get_n(%__MODULE__{out: nil} = state, :out), do: raise_direction_error(state, :out)
  def get_n(%__MODULE__{out: %Cipher{n: n}}, :out), do: n

  @spec set_n(__MODULE__.t(), :in | :out, Decibel.usable_nonce()) :: __MODULE__.t()
  def set_n(%__MODULE__{in: nil} = state, :in, _n), do: raise_direction_error(state, :in)

  def set_n(%__MODULE__{in: %Cipher{} = cin} = state, :in, n) do
    %__MODULE__{state | in: Cipher.set_nonce(cin, n)}
  end

  def set_n(%__MODULE__{out: nil} = state, :out, _n), do: raise_direction_error(state, :out)

  def set_n(%__MODULE__{out: %Cipher{n: current} = cout} = state, :out, n) do
    updated = Cipher.set_nonce(cout, n)

    if n < current do
      raise NonceError, reason: :rewind, nonce: n, current_nonce: current
    end

    %__MODULE__{state | out: updated}
  end

  defp raise_direction_error(%__MODULE__{mode: :split}, direction) do
    raise TransportDirectionError, direction: direction, cause: :split
  end

  defp raise_direction_error(%__MODULE__{}, direction) do
    raise TransportDirectionError, direction: direction
  end
end
