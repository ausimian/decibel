defmodule Decibel.Handshake do
  @moduledoc false
  use TypedStruct

  alias Decibel.Cipher
  alias Decibel.ChannelPair
  alias Decibel.{Crypto, Symmetric, Utility}

  typedstruct do
    field(:role, Decibel.role())
    field(:sym, Symmetric.t())
    field(:dh, Crypto.curve())
    field(:s, nil | Crypto.private_key(), default: nil)
    field(:rs, nil | Crypto.public_key(), default: nil)
    field(:e, nil | Crypto.private_key(), default: nil)
    field(:re, nil | Crypto.public_key(), default: nil)
    field(:psks, [<<_::256>>], default: [])
    field(:pskf, boolean(), default: false)
    field(:hs, list(), default: [])
    field(:buf, iodata(), default: [])
    field(:swap, Decibel.role())
  end

  @spec initialize(String.t(), Decibel.role(), map, Keyword.t()) :: __MODULE__.t()
  def initialize(<<protocol_name::binary>>, role, keys \\ %{}, opts \\ []) when role in [:ini, :rsp] and is_map(keys) do
    # Parse the protocol name to get the constituent parts
    {{hs_name, mods}, curve, cipher, hash} = Utility.parse_protocol_name(protocol_name)
    # Look up the handshake in the registry and apply any modifications
    reg = Keyword.get(opts, :registry, Decibel.Registry)

    {pre, hs} =
      hs_name
      |> reg.fetch!()
      |> Utility.split_handshake()
      |> Utility.modify_handshake(mods)

    # Check that any keys implied by the pre-message handshake are present
    Utility.has_premessage_keys(role, pre, keys) || raise "Missing pre-message keys"
    # Check that any pre-shared keys are present
    Utility.has_preshared_keys(hs, Map.get(keys, :psks, [])) || raise "Missing pre-shared keys"

    # Construct a new symmetric ciper, mixing any prologue and pre-message public keys
    # into the hash
    sym =
      Symmetric.initialize(cipher, hash, protocol_name)
      |> Symmetric.mix_hash(Map.get(keys, :prologue, []))

    # Get any private shared keys
    psks = keys[:psks] || []

    %__MODULE__{
      role: role,
      sym: sym,
      dh: curve,
      s: keys[:s],
      e: keys[:e],
      re: keys[:re],
      rs: keys[:rs],
      psks: psks,
      pskf: psks != [],
      hs: hs,
      swap: Keyword.get(opts, :swap, :ini)
    }
    |> mix_premessage_public_keys(pre)
  end

  @spec write_message(__MODULE__.t(), iodata()) :: {__MODULE__.t() | ChannelPair.t(), iodata()}
  def write_message(%__MODULE__{role: role, hs: [{role, tokens} | msgs]} = state, plaintext)
      when role in [:ini, :rsp] do
    %__MODULE__{state | hs: msgs}
    |> do_steps(tokens, &write_step/2)
    |> encrypt_and_hash(plaintext)
    |> maybe_split()
  end

  @spec read_message(__MODULE__.t(), iodata()) :: {__MODULE__.t() | ChannelPair.t(), iodata()}
  def read_message(%__MODULE__{role: role, hs: [{msg_role, tokens} | msgs]} = state, ciphertext)
      when role in [:ini, :rsp] and msg_role in [:ini, :rsp] and role != msg_role do
    %__MODULE__{state | hs: msgs, buf: IO.iodata_to_binary(ciphertext)}
    |> do_steps(tokens, &read_step/2)
    |> decrypt_and_hash()
    |> maybe_split()
  end

  defp do_steps(%__MODULE__{} = state, tokens, step), do: Enum.reduce(tokens, state, step)

  @spec write_step(:e | :s | :ee | :es | :se | :ss | :psk, __MODULE__.t()) :: __MODULE__.t()
  defp write_step(:e, %__MODULE__{sym: sym, buf: buf, e: e, dh: dh} = state) do
    case e do
      nil ->
        # Generate ephemeral key and continue. Ephemeral keys _are_ typically
        # generated, but repeatable testing requires that it be possible to
        # initialize them with known keys
        write_step(:e, %__MODULE__{state | e: Crypto.generate_keypair(dh)})

      {pub, _priv} ->
        case %__MODULE__{state | buf: [buf, pub], sym: Symmetric.mix_hash(sym, pub)} do
          %__MODULE__{pskf: false} = state ->
            state

          %__MODULE__{sym: sym} = state ->
            %__MODULE__{state | sym: Symmetric.mix_key(sym, pub)}
        end
    end
  end

  defp write_step(:s, %__MODULE__{s: {pub, _}, sym: sym, buf: buf} = state) do
    {sym, ciphertext} = Symmetric.encrypt_and_hash(sym, pub)
    %__MODULE__{state | buf: [buf, ciphertext], sym: sym}
  end

  defp write_step(t, state), do: common_step(t, state)

  defp read_step(:e, %__MODULE__{re: nil, sym: sym, dh: dh, buf: buf} = state) do
    key_len = Crypto.dh_len(dh)
    <<re::binary-size(key_len), rest::binary>> = buf

    case %__MODULE__{state | sym: Symmetric.mix_hash(sym, re), re: re, buf: rest} do
      %__MODULE__{pskf: false} = state ->
        state

      %__MODULE__{sym: sym, re: re} = state ->
        %__MODULE__{state | sym: Symmetric.mix_key(sym, re)}
    end
  end

  defp read_step(:s, %__MODULE__{rs: nil, sym: sym, dh: dh, buf: buf} = state) do
    key_len = Crypto.dh_len(dh) + if has_key?(sym), do: 16, else: 0
    <<temp::binary-size(key_len), rest::binary>> = buf
    {sym, rs} = Symmetric.decrypt_and_hash(sym, temp)
    %__MODULE__{state | sym: sym, rs: rs, buf: rest}
  end

  defp read_step(t, state), do: common_step(t, state)

  @spec common_step(:ee | :es | :se | :ss | :psk, __MODULE__.t()) :: __MODULE__.t()
  defp common_step(:ee, %__MODULE__{sym: sym, dh: dh, e: e, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, e, re))}
  end

  defp common_step(:es, %__MODULE__{role: :ini, sym: sym, dh: dh, e: e, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, e, rs))}
  end

  defp common_step(:es, %__MODULE__{role: :rsp, sym: sym, dh: dh, s: s, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, s, re))}
  end

  defp common_step(:se, %__MODULE__{role: :ini, sym: sym, dh: dh, s: s, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, s, re))}
  end

  defp common_step(:se, %__MODULE__{role: :rsp, sym: sym, dh: dh, e: e, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, e, rs))}
  end

  defp common_step(:ss, %__MODULE__{sym: sym, dh: dh, s: s, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, Crypto.dh(dh, s, rs))}
  end

  defp common_step(:psk, %__MODULE__{sym: sym, psks: [psk | psks]} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key_and_hash(sym, psk), psks: psks}
  end

  defp maybe_split(%__MODULE__{hs: hs, sym: sym, buf: buf, role: role, swap: swap} = state) do
    case hs do
      [] ->
        {Symmetric.split(sym, role === swap), buf}

      _ ->
        {%__MODULE__{state | buf: []}, buf}
    end
  end

  defp encrypt_and_hash(%__MODULE__{sym: sym, buf: buf} = state, plaintext) do
    {%Symmetric{} = sym, ciphertext} = Symmetric.encrypt_and_hash(sym, plaintext)
    %__MODULE__{state | sym: sym, buf: [buf, ciphertext]}
  end

  defp decrypt_and_hash(%__MODULE__{sym: sym, buf: buf} = state) do
    {%Symmetric{} = sym, plaintext} = Symmetric.decrypt_and_hash(sym, buf)
    %__MODULE__{state | sym: sym, buf: plaintext}
  end

  defp mix_premessage_public_keys(%__MODULE__{} = hs, []), do: hs
  defp mix_premessage_public_keys(%__MODULE__{} = hs, [{_, []} | rest]), do: mix_premessage_public_keys(hs, rest)

  defp mix_premessage_public_keys(%__MODULE__{sym: sym} = hs, [{msg_role, [token | tokens]} | rest]) do
    case token do
      :e ->
        public_key = if msg_role === hs.role, do: elem(hs.e, 0), else: hs.re

        case %__MODULE__{hs | sym: Symmetric.mix_hash(sym, public_key)} do
          %__MODULE__{pskf: true, sym: sym} = hs when token === :e ->
            %__MODULE__{hs | sym: Symmetric.mix_key(sym, public_key)}

          %__MODULE__{} = hs ->
            hs
        end

      :s ->
        public_key = if msg_role === hs.role, do: elem(hs.s, 0), else: hs.rs
        %__MODULE__{hs | sym: Symmetric.mix_hash(sym, public_key)}
    end
    |> mix_premessage_public_keys([{msg_role, tokens} | rest])
  end

  defp has_key?(%Symmetric{cs: %Cipher{k: k}}), do: k != nil
end
