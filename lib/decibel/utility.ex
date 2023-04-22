defmodule Decibel.Utility do
  @moduledoc false
  alias Decibel.Crypto

  defguardp is_handshake_char(ch) when (ch >= ?A and ch <= ?Z) or (ch >= ?0 and ch <= ?9)

  @sep {:..., []}

  @spec parse_protocol_name(String.t()) :: {{String.t(), list}, Crypto.curve(), Crypto.cipher(), Crypto.hash()}
  def parse_protocol_name(<<"Noise_", rest::binary>>) do
    [handshake, curve, cipher, hash] = String.split(rest, "_", trim: true)
    {parse_handshake(handshake), to_curve(curve), to_cipher(cipher), to_hash(hash)}
  end

  @spec parse_handshake(String.t()) :: {String.t(), list}
  def parse_handshake(hs), do: parse_handshake(hs, [])

  @spec split_handshake(list()) :: {list(), list()}
  def split_handshake(hs) when is_list(hs) do
    if index = Enum.find_index(hs, &match?(@sep, &1)) do
      {Enum.take(hs, index), Enum.drop(hs, index + 1)}
    else
      {[], hs}
    end
  end

  @spec modify_handshake({list(), list()}, list()) :: {list(), list()}
  def modify_handshake({pre, post}, mods) when is_list(pre) and is_list(post) and is_list(mods) do
    for mod <- mods, reduce: {pre, post} do
      {pre, post} ->
        case mod do
          :fallback ->
            {pre ++ [hd(post)], tl(post)}

          {:psk, 0} ->
            [{role, tokens} | rest] = post
            {pre, [{role, [:psk | tokens]} | rest]}

          {:psk, n} when n > 0 ->
            {pre, List.update_at(post, n - 1, fn {role, tokens} -> {role, tokens ++ [:psk]} end)}
        end
    end
  end

  @spec has_premessage_keys(:ini | :rsp, list(), map()) :: boolean
  def has_premessage_keys(_, [], _), do: true
  def has_premessage_keys(_, msgs, []), do: length(msgs) == 0
  def has_premessage_keys(role, [{_, []} | msgs], keys), do: has_premessage_keys(role, msgs, keys)
  def has_premessage_keys(role, [{sender, [token | tokens]} | msgs], keys)
      when role in [:ini, :rsp] and sender in [:ini, :rsp] do
    reqd =
      case token do
        :e -> if role == sender, do: :e, else: :re
        :s -> if role == sender, do: :s, else: :rs
      end

    case Map.pop(keys, reqd) do
      {{_pub, _priv}, new_keys} when reqd in [:e, :s] ->
        has_premessage_keys(role, [{sender, tokens} | msgs], new_keys)

      {pub, new_keys} when is_binary(pub) and reqd in [:re, :rs] ->
        has_premessage_keys(role, [{sender, tokens} | msgs], new_keys)

      _ ->
        false
    end
  end

  @spec has_preshared_keys(msgs :: list(), keys :: list()) :: boolean
  def has_preshared_keys([], _), do: true
  def has_preshared_keys([{_, []} | msgs], psks), do: has_preshared_keys(msgs, psks)
  def has_preshared_keys([{_, [:psk | _]} | _], []), do: false

  def has_preshared_keys([{role, [:psk | tokens]} | msgs], [<<_::binary-size(32)>> | psks]) do
    has_preshared_keys([{role, tokens} | msgs], psks)
  end

  def has_preshared_keys([{role, [_ | tokens]} | msgs], psks) do
    has_preshared_keys([{role, tokens} | msgs], psks)
  end

  defp to_curve("25519"), do: :x25519
  defp to_curve("448"), do: :x448

  defp to_cipher("AESGCM"), do: :aes_256_gcm
  defp to_cipher("ChaChaPoly"), do: :chacha20_poly1305

  defp to_hash("SHA256"), do: :sha256
  defp to_hash("SHA512"), do: :sha512
  defp to_hash("BLAKE2s"), do: :blake2s
  defp to_hash("BLAKE2b"), do: :blake2b

  defp parse_handshake(<<ch, rest::binary>>, hs) when is_handshake_char(ch) do
    parse_handshake(rest, [ch | hs])
  end

  defp parse_handshake(<<rest::binary>>, hs) do
    hs = List.to_string(:lists.reverse(hs))
    mods = for m <- String.split(rest, "+", trim: true), do: to_modifier(m)
    {hs, mods}
  end

  defp to_modifier("fallback"), do: :fallback
  defp to_modifier(<<"psk", n::binary>>), do: {:psk, String.to_integer(n)}
end
