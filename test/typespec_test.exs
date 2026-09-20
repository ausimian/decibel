defmodule Decibel.TypespecTest do
  use ExUnit.Case, async: true

  test "handshake hashes have exactly the two Noise HASHLEN sizes" do
    {:"::", _, [_name, {:|, _, hash_types}]} = type!(Decibel, :handshake_hash)

    assert Enum.map(hash_types, &bitstring_size!/1) == [256, 512]
  end

  test "handshake state stores local static and ephemeral keypairs" do
    {:"::", _, [_name, {:{}, _, keypair_types}]} = type!(Decibel, :keypair)
    fields = struct_fields!(Decibel.Handshake)

    assert Enum.all?(keypair_types, &match?({:binary, _, []}, &1))

    for field <- [:s, :e] do
      assert remote_type?(Keyword.fetch!(fields, field), Decibel, :keypair)
    end
  end

  test "public nonce types preserve the usable and reserved boundaries" do
    assert range!(Decibel, :nonce) == {0, 18_446_744_073_709_551_615}
    assert range!(Decibel, :usable_nonce) == {0, 18_446_744_073_709_551_614}
  end

  test "channel pairs retain the selected HASHLEN in their field and constructor" do
    fields = struct_fields!(Decibel.ChannelPair)

    assert remote_type?(Keyword.fetch!(fields, :h), Decibel, :handshake_hash)
    assert remote_type?(spec!(Decibel.ChannelPair, :new, 5), Decibel, :handshake_hash)
  end

  test "public function specs use the opaque session type, not bare references" do
    refute Decibel
           |> specs!()
           |> Enum.any?(&local_type?(&1, :reference))
  end

  defp type!(module, name) do
    {:ok, types} = Code.Typespec.fetch_types(module)

    {_kind, type} =
      Enum.find(types, fn {_kind, {type_name, _definition, _arguments}} ->
        type_name == name
      end)

    Code.Typespec.type_to_quoted(type)
  end

  defp struct_fields!(module) do
    {:"::", _, [_name, {:%, _, [^module, {:%{}, _, fields}]}]} = type!(module, :t)
    fields
  end

  defp range!(module, name) do
    {:"::", _, [_name, {:.., _, [first, last]}]} = type!(module, name)
    {first, last}
  end

  defp bitstring_size!({:<<>>, _, [{:"::", _, [{:_, _, _}, size]}]}), do: size

  defp spec!(module, name, arity) do
    {:ok, specs} = Code.Typespec.fetch_specs(module)
    {{^name, ^arity}, [definition]} = List.keyfind(specs, {name, arity}, 0)
    Code.Typespec.spec_to_quoted(name, definition)
  end

  defp specs!(module) do
    {:ok, specs} = Code.Typespec.fetch_specs(module)

    for {{name, _arity}, definitions} <- specs,
        definition <- definitions do
      Code.Typespec.spec_to_quoted(name, definition)
    end
  end

  defp remote_type?(quoted, module, name) do
    {_quoted, found?} =
      Macro.prewalk(quoted, false, fn
        {{:., _, [^module, ^name]}, _, []} = node, _found? -> {node, true}
        node, found? -> {node, found?}
      end)

    found?
  end

  defp local_type?(quoted, name) do
    {_quoted, found?} =
      Macro.prewalk(quoted, false, fn
        {^name, _, []} = node, _found? -> {node, true}
        node, found? -> {node, found?}
      end)

    found?
  end
end
