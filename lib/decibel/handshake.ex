defmodule Decibel.Handshake do
  @moduledoc false
  use TypedStruct

  alias Decibel.{ChannelPair, Cipher, Crypto, DecryptionError, Symmetric, Utility}

  @invalid_psks "pre-shared keys must contain exactly one 32-byte key per psk modifier"

  @type initialization_mode :: :safe | :unsafe_test_ephemeral
  @type keypair :: {Crypto.public_key(), Crypto.private_key()}

  typedstruct do
    field(:role, Decibel.role())
    field(:sym, Symmetric.t())
    field(:dh, Crypto.curve())
    field(:s, nil | Crypto.private_key(), default: nil)
    field(:rs, nil | Crypto.public_key(), default: nil)
    field(:e, nil | keypair(), default: nil)
    field(:unsafe_ephemeral, nil | keypair(), default: nil)
    field(:re, nil | Crypto.public_key(), default: nil)
    field(:psks, [<<_::256>>], default: [])
    field(:pskf, boolean(), default: false)
    field(:hs, list(), default: [])
    field(:buf, iodata(), default: [])
    field(:swap, Decibel.role())
    field(:mode, ChannelPair.mode())
  end

  @spec initialize(String.t(), Decibel.role(), map, Keyword.t(), initialization_mode()) :: __MODULE__.t()
  def initialize(<<protocol_name::binary>>, role, keys \\ %{}, opts \\ [], mode \\ :safe)
      when role in [:ini, :rsp] and is_map(keys) and mode in [:safe, :unsafe_test_ephemeral] do
    # Parse the protocol name to get the constituent parts
    {{hs_name, mods}, curve, cipher, hash} = Utility.parse_protocol_name(protocol_name)
    # Look up the handshake in the registry and apply any modifications
    registry = registry_option!(opts)

    {pre, hs} =
      registry
      |> fetch_handshake!(hs_name)
      |> Utility.split_handshake()
      |> Utility.modify_handshake(mods)

    {e, unsafe_ephemeral, re} = prepare_ephemeral_keys!(pre, mods, role, curve, keys, mode)

    # Preserve pre-message and PSK validation precedence while extending the
    # static-key check across the fully modified handshake pattern.
    key_length = Crypto.dh_len(curve)
    pre_requirements = Utility.required_static_keys(role, {pre, []})
    validate_required_static_keys!(pre_requirements, key_length, keys)
    # Check that any pre-shared keys are present
    psks = Map.get(keys, :psks, [])
    Utility.has_preshared_keys(hs, psks) || raise ArgumentError, @invalid_psks

    swap = validate_options!(opts)
    {s, rs} = prepare_static_keys!(Utility.required_static_keys(role, {pre, hs}), key_length, keys)
    prologue = validate_prologue!(Map.get(keys, :prologue, []))

    # Construct a new symmetric ciper, mixing any prologue and pre-message public keys
    # into the hash
    sym =
      Symmetric.initialize(cipher, hash, protocol_name)
      |> Symmetric.mix_hash(prologue)

    %__MODULE__{
      role: role,
      sym: sym,
      dh: curve,
      s: s,
      e: e,
      unsafe_ephemeral: unsafe_ephemeral,
      re: re,
      rs: rs,
      psks: psks,
      pskf: psks != [],
      hs: hs,
      swap: swap,
      mode: if(hs_name in ["N", "K", "X"], do: :one_way, else: :interactive)
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

  defp do_steps(%__MODULE__{} = state, tokens, step) do
    Enum.reduce(tokens, state, fn token, state ->
      try do
        step.(token, state)
      rescue
        e in DecryptionError ->
          reraise with_remote_keys(e, state), __STACKTRACE__
      end
    end)
  end

  @spec write_step(:e | :s | :ee | :es | :se | :ss | :psk, __MODULE__.t()) :: __MODULE__.t()
  defp write_step(:e, %__MODULE__{sym: sym, buf: buf, unsafe_ephemeral: override, dh: dh} = state) do
    {pub, _priv} = e = override || Crypto.generate_keypair(dh)

    case %__MODULE__{
      state
      | e: e,
        unsafe_ephemeral: nil,
        buf: [buf, pub],
        sym: Symmetric.mix_hash(sym, pub)
    } do
      %__MODULE__{pskf: false} = state ->
        state

      %__MODULE__{sym: sym} = state ->
        %__MODULE__{state | sym: Symmetric.mix_key(sym, pub)}
    end
  end

  defp write_step(:s, %__MODULE__{s: {pub, _}, sym: sym, buf: buf} = state) do
    {sym, ciphertext} = Symmetric.encrypt_and_hash(sym, pub)
    %__MODULE__{state | buf: [buf, ciphertext], sym: sym}
  end

  defp write_step(t, state), do: common_step(t, state)

  defp read_step(:e, %__MODULE__{re: nil, sym: sym, dh: dh, buf: buf} = state) do
    key_len = Crypto.dh_len(dh)
    {re, rest} = take_bytes!(buf, key_len)

    case %__MODULE__{state | sym: Symmetric.mix_hash(sym, re), re: re, buf: rest} do
      %__MODULE__{pskf: false} = state ->
        state

      %__MODULE__{sym: sym, re: re} = state ->
        %__MODULE__{state | sym: Symmetric.mix_key(sym, re)}
    end
  end

  defp read_step(:s, %__MODULE__{rs: nil, sym: sym, dh: dh, buf: buf} = state) do
    key_len = Crypto.dh_len(dh) + if has_key?(sym), do: 16, else: 0
    {temp, rest} = take_bytes!(buf, key_len)
    {sym, rs} = Symmetric.decrypt_and_hash(sym, temp)
    %__MODULE__{state | sym: sym, rs: rs, buf: rest}
  end

  defp read_step(t, state), do: common_step(t, state)

  @spec common_step(:ee | :es | :se | :ss | :psk, __MODULE__.t()) :: __MODULE__.t()
  defp common_step(:ee, %__MODULE__{sym: sym, dh: dh, e: e, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, e, re))}
  end

  defp common_step(:es, %__MODULE__{role: :ini, sym: sym, dh: dh, e: e, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, e, rs))}
  end

  defp common_step(:es, %__MODULE__{role: :rsp, sym: sym, dh: dh, s: s, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, s, re))}
  end

  defp common_step(:se, %__MODULE__{role: :ini, sym: sym, dh: dh, s: s, re: re} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, s, re))}
  end

  defp common_step(:se, %__MODULE__{role: :rsp, sym: sym, dh: dh, e: e, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, e, rs))}
  end

  defp common_step(:ss, %__MODULE__{sym: sym, dh: dh, s: s, rs: rs} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key(sym, dh(dh, s, rs))}
  end

  defp common_step(:psk, %__MODULE__{sym: sym, psks: [psk | psks]} = state) do
    %__MODULE__{state | sym: Symmetric.mix_key_and_hash(sym, psk), psks: psks}
  end

  defp maybe_split(%__MODULE__{hs: hs, sym: sym, buf: buf, role: role, swap: swap, mode: mode, rs: rs} = state) do
    case hs do
      [] ->
        {Symmetric.split(sym, mode, role, swap, rs), buf}

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
  rescue
    e in DecryptionError ->
      reraise with_remote_keys(e, state), __STACKTRACE__
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

  defp prepare_ephemeral_keys!(pre, mods, role, curve, keys, mode) do
    fallback? = :fallback in mods
    local_premessage? = fallback? and ephemeral_premessage?(pre, role)
    remote_premessage? = fallback? and ephemeral_premessage?(pre, opposite(role))
    key_length = Crypto.dh_len(curve)

    {e, unsafe_ephemeral} =
      prepare_local_ephemeral!(Map.fetch(keys, :e), mode, local_premessage?, key_length)

    re = prepare_remote_ephemeral!(Map.fetch(keys, :re), remote_premessage?, key_length)

    {e, unsafe_ephemeral, re}
  end

  defp prepare_static_keys!(required, key_length, keys) do
    s =
      case Map.fetch(keys, :s) do
        {:ok, value} -> validate_keypair!(value, key_length, "local static key :s")
        :error -> required_static_key!(required, :s)
      end

    rs =
      case Map.fetch(keys, :rs) do
        {:ok, value} -> prepare_remote_static!(value, required, key_length)
        :error -> required_static_key!(required, :rs)
      end

    {s, rs}
  end

  defp prepare_remote_static!(value, required, key_length) do
    if :rs in required do
      validate_public_key!(value, key_length, "remote static key :rs")
    else
      raise ArgumentError, "caller-supplied :rs is only permitted for a remote static pre-message"
    end
  end

  defp required_static_key!(required, :s) do
    if :s in required do
      raise ArgumentError, "local static key :s is required by the selected handshake pattern"
    end
  end

  defp required_static_key!(required, :rs) do
    if :rs in required do
      raise ArgumentError, "remote static key :rs is required by a pre-message"
    end
  end

  defp validate_required_static_keys!(required, key_length, keys) do
    if :s in required do
      case Map.fetch(keys, :s) do
        {:ok, value} -> validate_keypair!(value, key_length, "local static key :s")
        :error -> raise ArgumentError, "local static key :s is required by the selected handshake pattern"
      end
    end

    if :rs in required do
      case Map.fetch(keys, :rs) do
        {:ok, value} -> validate_public_key!(value, key_length, "remote static key :rs")
        :error -> raise ArgumentError, "remote static key :rs is required by a pre-message"
      end
    end

    :ok
  end

  defp prepare_local_ephemeral!(:error, _mode, true, _key_length) do
    raise ArgumentError, "fallback :e is required by a local pre-message"
  end

  defp prepare_local_ephemeral!(:error, _mode, false, _key_length), do: {nil, nil}

  defp prepare_local_ephemeral!({:ok, e}, _mode, true, key_length) do
    {validate_keypair!(e, key_length, "fallback :e"), nil}
  end

  defp prepare_local_ephemeral!({:ok, _e}, :safe, false, _key_length) do
    raise ArgumentError,
          "caller-supplied :e is only permitted for a local fallback pre-message"
  end

  defp prepare_local_ephemeral!({:ok, e}, :unsafe_test_ephemeral, false, key_length) do
    {nil, validate_keypair!(e, key_length, "unsafe :e")}
  end

  defp prepare_remote_ephemeral!(:error, true, _key_length) do
    raise ArgumentError, "fallback :re is required by a remote pre-message"
  end

  defp prepare_remote_ephemeral!(:error, false, _key_length), do: nil

  defp prepare_remote_ephemeral!({:ok, re}, true, key_length) do
    validate_public_key!(re, key_length, "fallback :re")
  end

  defp prepare_remote_ephemeral!({:ok, _re}, false, _key_length) do
    raise ArgumentError,
          "caller-supplied :re is only permitted for a remote fallback pre-message"
  end

  defp ephemeral_premessage?(pre, role) do
    Enum.any?(pre, fn
      {^role, tokens} -> :e in tokens
      {_other_role, _tokens} -> false
    end)
  end

  defp opposite(:ini), do: :rsp
  defp opposite(:rsp), do: :ini

  defp validate_keypair!({public, private} = keypair, key_length, _description)
       when is_binary(public) and byte_size(public) == key_length and is_binary(private) and
              byte_size(private) == key_length do
    keypair
  end

  defp validate_keypair!(_keypair, key_length, description) do
    raise ArgumentError,
          "#{description} must be a keypair containing #{key_length}-byte public and private keys"
  end

  defp validate_public_key!(public, key_length, _description)
       when is_binary(public) and byte_size(public) == key_length do
    public
  end

  defp validate_public_key!(_public, key_length, description) do
    raise ArgumentError, "#{description} must be a #{key_length}-byte public key"
  end

  defp registry_option!(opts) do
    Keyword.keyword?(opts) || raise ArgumentError, "options must be a keyword list"

    case Keyword.get_values(opts, :registry) do
      [] ->
        Decibel.Registry

      [registry] ->
        validate_registry!(registry)

      _registries ->
        raise ArgumentError, "construction option :registry may only be specified once"
    end
  end

  defp validate_options!(opts) do
    case Enum.find(Keyword.keys(opts), &(&1 not in [:registry, :swap])) do
      nil -> :ok
      key -> raise ArgumentError, "unsupported construction option: #{inspect(key)}"
    end

    case Enum.find([:registry, :swap], &(length(Keyword.get_values(opts, &1)) > 1)) do
      nil -> :ok
      key -> raise ArgumentError, "construction option #{inspect(key)} may only be specified once"
    end

    case Keyword.get(opts, :swap, :ini) do
      swap when swap in [:ini, :rsp] -> swap
      _swap -> raise ArgumentError, "construction option :swap must be :ini or :rsp"
    end
  end

  defp validate_registry!(registry) when is_atom(registry) do
    if Code.ensure_loaded?(registry) and function_exported?(registry, :fetch!, 1) do
      registry
    else
      raise ArgumentError, "construction option :registry must be a module exporting fetch!/1"
    end
  end

  defp validate_registry!(_registry) do
    raise ArgumentError, "construction option :registry must be a module exporting fetch!/1"
  end

  defp validate_prologue!(prologue) do
    :erlang.iolist_size(prologue)
    prologue
  rescue
    _error in ArgumentError ->
      reraise ArgumentError, [message: "prologue must be valid iodata"], __STACKTRACE__
  end

  defp has_key?(%Symmetric{cs: %Cipher{k: k}}), do: k != nil

  defp fetch_handshake!(registry, name) do
    registry.fetch!(name)
  rescue
    _error in KeyError ->
      reraise ArgumentError,
              [message: "invalid Noise protocol name: unsupported handshake pattern #{inspect(name)}"],
              __STACKTRACE__
  end

  defp take_bytes!(bytes, length) when byte_size(bytes) >= length do
    <<field::binary-size(^length), rest::binary>> = bytes
    {field, rest}
  end

  defp take_bytes!(_bytes, _length), do: raise(DecryptionError, reason: :truncated)

  defp dh(curve, keypair, public_key) do
    Crypto.dh(curve, keypair, public_key)
  rescue
    _error in ErlangError ->
      reraise DecryptionError, [reason: :invalid_public_key], __STACKTRACE__
  end

  defp with_remote_keys(%DecryptionError{} = error, %__MODULE__{re: re, rs: rs}) do
    %DecryptionError{error | remote_keys: [re: re, rs: rs]}
  end
end
