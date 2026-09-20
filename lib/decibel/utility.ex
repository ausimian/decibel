defmodule Decibel.Utility do
  @moduledoc false
  alias Decibel.Crypto

  @type modifier :: :fallback | {:psk, non_neg_integer()}
  @type handshake_token :: :e | :s | :ee | :es | :se | :ss | :psk
  @type handshake_message :: {Decibel.role(), [handshake_token()]}
  @type separator :: {:..., []}
  @type registry_pattern :: [handshake_message() | separator()]
  @type handshake_pattern :: {[handshake_message()], [handshake_message()]}
  @type parsed_handshake :: {String.t(), [modifier()]}
  @type parsed_protocol :: {parsed_handshake(), Crypto.curve(), Crypto.cipher(), Crypto.hash()}
  @type static_key :: :s | :rs

  @max_protocol_name_size 255
  @name_section ~r/\A[A-Za-z0-9+\/]+\z/
  @handshake_section ~r/\A([A-Z0-9]+)(.*)\z/
  @modifier_name ~r/\A[a-z][a-z0-9]*\z/
  @psk_modifier ~r/\Apsk(0|[1-9][0-9]*)\z/

  @sep {:..., []}

  @spec parse_protocol_name(String.t()) :: parsed_protocol()
  def parse_protocol_name(protocol_name) when is_binary(protocol_name) do
    if byte_size(protocol_name) > @max_protocol_name_size do
      invalid_protocol_name!("must not exceed #{@max_protocol_name_size} bytes")
    end

    case String.split(protocol_name, "_", trim: false) do
      ["Noise", handshake, curve, cipher, hash] ->
        sections = [handshake, curve, cipher, hash]

        if Enum.all?(sections, &valid_name_section?/1) do
          {parse_handshake(handshake), to_curve(curve), to_cipher(cipher), to_hash(hash)}
        else
          invalid_protocol_name!("expected Noise_<handshake>_<dh>_<cipher>_<hash>")
        end

      _ ->
        invalid_protocol_name!("expected Noise_<handshake>_<dh>_<cipher>_<hash>")
    end
  end

  @spec parse_handshake(String.t()) :: parsed_handshake()
  def parse_handshake(handshake) when is_binary(handshake) do
    case Regex.run(@handshake_section, handshake) do
      [_, name, ""] ->
        {name, []}

      [_, name, modifiers] ->
        {name, parse_modifiers(modifiers)}

      _ ->
        invalid_protocol_name!("invalid handshake pattern section")
    end
  end

  @spec split_handshake(registry_pattern()) :: handshake_pattern()
  def split_handshake(hs) when is_list(hs) do
    if index = Enum.find_index(hs, &match?(@sep, &1)) do
      {Enum.take(hs, index), Enum.drop(hs, index + 1)}
    else
      {[], hs}
    end
  end

  @spec modify_handshake(handshake_pattern(), [modifier()]) :: handshake_pattern()
  def modify_handshake({pre, post}, mods) when is_list(pre) and is_list(post) and is_list(mods) do
    Enum.reduce(mods, {pre, post}, &apply_modifier/2)
  end

  @spec required_static_keys(Decibel.role(), handshake_pattern()) :: [static_key()]
  def required_static_keys(role, {pre, messages}) when role in [:ini, :rsp] do
    local_required? =
      Enum.any?(pre ++ messages, fn {sender, tokens} ->
        (sender == role and :s in tokens) or local_static_dh?(role, tokens)
      end)

    remote_required? =
      Enum.any?(pre, fn {sender, tokens} ->
        sender != role and :s in tokens
      end)

    Enum.filter([s: local_required?, rs: remote_required?], &elem(&1, 1))
    |> Keyword.keys()
  end

  @spec has_preshared_keys([handshake_message()], term()) :: boolean
  def has_preshared_keys(msgs, psks) when is_list(msgs) and is_list(psks) do
    required =
      Enum.reduce(msgs, 0, fn {_role, tokens}, count ->
        count + Enum.count(tokens, &(&1 == :psk))
      end)

    length(psks) == required and Enum.all?(psks, &match?(<<_::binary-size(32)>>, &1))
  end

  def has_preshared_keys(_msgs, _psks), do: false

  defp to_curve("25519"), do: :x25519
  defp to_curve("448"), do: :x448
  defp to_curve(curve), do: invalid_protocol_name!("unsupported DH function #{inspect(curve)}")

  defp to_cipher("AESGCM"), do: :aes_256_gcm
  defp to_cipher("ChaChaPoly"), do: :chacha20_poly1305
  defp to_cipher(cipher), do: invalid_protocol_name!("unsupported cipher function #{inspect(cipher)}")

  defp to_hash("SHA256"), do: :sha256
  defp to_hash("SHA512"), do: :sha512
  defp to_hash("BLAKE2s"), do: :blake2s
  defp to_hash("BLAKE2b"), do: :blake2b
  defp to_hash(hash), do: invalid_protocol_name!("unsupported hash function #{inspect(hash)}")

  defp local_static_dh?(:ini, tokens), do: Enum.any?(tokens, &(&1 in [:se, :ss]))
  defp local_static_dh?(:rsp, tokens), do: Enum.any?(tokens, &(&1 in [:es, :ss]))

  defp apply_modifier(:fallback, {pre, [{:ini, tokens} = first | rest]})
       when tokens in [[:e], [:s], [:e, :s]] do
    {pre ++ [first], rest}
  end

  defp apply_modifier(:fallback, _pattern) do
    invalid_protocol_name!("fallback is not applicable to this handshake pattern")
  end

  defp apply_modifier({:psk, 0}, {pre, [{role, tokens} | rest]}) do
    {pre, [{role, [:psk | tokens]} | rest]}
  end

  defp apply_modifier({:psk, 0}, _pattern), do: invalid_psk_index!(0)

  defp apply_modifier({:psk, n}, {pre, post}) when n > 0 do
    case Enum.fetch(post, n - 1) do
      {:ok, {role, tokens}} ->
        {pre, List.replace_at(post, n - 1, {role, tokens ++ [:psk]})}

      :error ->
        invalid_psk_index!(n)
    end
  end

  defp parse_modifiers(modifiers) do
    names = String.split(modifiers, "+", trim: false)

    if Enum.any?(names, &(not Regex.match?(@modifier_name, &1))) do
      invalid_protocol_name!("invalid handshake pattern section")
    end

    parsed = Enum.map(names, &to_modifier/1)
    validate_unique_modifiers!(names)
    validate_modifier_order!(names)
    parsed
  end

  defp to_modifier("fallback"), do: :fallback

  defp to_modifier(name) do
    case Regex.run(@psk_modifier, name) do
      [_, n] -> {:psk, String.to_integer(n)}
      _ -> invalid_protocol_name!("unsupported modifier #{inspect(name)}")
    end
  end

  defp validate_unique_modifiers!(names) do
    case Enum.find(names, &(Enum.count(names, fn name -> name == &1 end) > 1)) do
      nil -> :ok
      duplicate -> invalid_protocol_name!("duplicate modifier #{inspect(duplicate)}")
    end
  end

  defp validate_modifier_order!(names) do
    # Noise section 8.1 requires modifiers whose order does not matter to be
    # sorted alphabetically. PSK modifiers commute within each run; fallback
    # separates runs because it changes subsequent message indices.
    # https://noiseprotocol.org/noise.html#handshake-pattern-name-section
    names
    |> Enum.chunk_by(&(&1 == "fallback"))
    |> Enum.each(fn
      ["fallback"] ->
        :ok

      psk_names ->
        if psk_names != Enum.sort(psk_names) do
          invalid_protocol_name!("psk modifiers must be listed in canonical order")
        end
    end)
  end

  @spec invalid_psk_index!(non_neg_integer()) :: no_return()
  defp invalid_psk_index!(n) do
    invalid_protocol_name!("psk#{n} does not reference a handshake message")
  end

  defp valid_name_section?(section) do
    section != "" and Regex.match?(@name_section, section)
  end

  defp invalid_protocol_name!(reason) do
    raise ArgumentError, "invalid Noise protocol name: #{reason}"
  end
end
