defmodule Decibel.Registry do
  @moduledoc false
  @handshakes %{
    # One way patterns

    "N" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es]
    ],
    "K" => [
      ini: [:s],
      rsp: [:s],
      ...: [],
      ini: [:e, :es, :ss]
    ],
    "X" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es, :s, :ss]
    ],

    # Fundamental interactive patterns

    "NN" => [
      ini: [:e],
      rsp: [:e, :ee]
    ],
    "KN" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :se]
    ],
    "NK" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es],
      rsp: [:e, :ee]
    ],
    "KK" => [
      ini: [:s],
      rsp: [:s],
      ...: [],
      ini: [:e, :es, :ss],
      rsp: [:e, :ee, :se]
    ],
    "NX" => [
      ini: [:e],
      rsp: [:e, :ee, :s, :es]
    ],
    "KX" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :se, :s, :es]
    ],
    "XN" => [
      ini: [:e],
      rsp: [:e, :ee],
      ini: [:s, :se]
    ],
    "IN" => [
      ini: [:e, :s],
      rsp: [:e, :ee, :se]
    ],
    "XK" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es],
      rsp: [:e, :ee],
      ini: [:s, :se]
    ],
    "IK" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es, :s, :ss],
      rsp: [:e, :ee, :se]
    ],
    "XX" => [
      ini: [:e],
      rsp: [:e, :ee, :s, :es],
      ini: [:s, :se]
    ],
    "IX" => [
      ini: [:e, :s],
      rsp: [:e, :ee, :se, :s, :es]
    ],

    # Deferred patterns

    "NK1" => [
      rsp: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :es]
    ],
    "NX1" => [
      ini: [:e],
      rsp: [:e, :ee, :s],
      ini: [:es]
    ],
    "X1N" => [
      ini: [:e],
      rsp: [:e, :ee],
      ini: [:s],
      rsp: [:se]
    ],
    "X1K" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es],
      rsp: [:e, :ee],
      ini: [:s],
      rsp: [:se]
    ],
    "XK1" => [
      rsp: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :es],
      ini: [:s, :se]
    ],
    "X1K1" => [
      rsp: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :es],
      ini: [:s],
      rsp: [:se]
    ],
    "X1X" => [
      ini: [:e],
      rsp: [:e, :ee, :s, :es],
      ini: [:s],
      rsp: [:se]
    ],
    "XX1" => [
      ini: [:e],
      rsp: [:e, :ee, :s],
      ini: [:es, :s, :se]
    ],
    "X1X1" => [
      ini: [:e],
      rsp: [:e, :ee, :s],
      ini: [:es, :s],
      rsp: [:se]
    ],
    "K1N" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee],
      ini: [:se]
    ],
    "K1K" => [
      ini: [:s],
      rsp: [:s],
      ...: [],
      ini: [:e, :es],
      rsp: [:e, :ee],
      ini: [:se]
    ],
    "KK1" => [
      ini: [:s],
      rsp: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :se, :es]
    ],
    "K1K1" => [
      ini: [:s],
      rsp: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :es],
      ini: [:se]
    ],
    "K1X" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :s, :es],
      ini: [:se]
    ],
    "KX1" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :se, :s],
      ini: [:es]
    ],
    "K1X1" => [
      ini: [:s],
      ...: [],
      ini: [:e],
      rsp: [:e, :ee, :s],
      ini: [:se, :es]
    ],
    "I1N" => [
      ini: [:e, :s],
      rsp: [:e, :ee],
      ini: [:se]
    ],
    "I1K" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :es, :s],
      rsp: [:e, :ee],
      ini: [:se]
    ],
    "IK1" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :s],
      rsp: [:e, :ee, :se, :es]
    ],
    "I1K1" => [
      rsp: [:s],
      ...: [],
      ini: [:e, :s],
      rsp: [:e, :ee, :es],
      ini: [:se]
    ],
    "I1X" => [
      ini: [:e, :s],
      rsp: [:e, :ee, :s, :es],
      ini: [:se]
    ],
    "IX1" => [
      ini: [:e, :s],
      rsp: [:e, :ee, :se, :s],
      ini: [:es]
    ],
    "I1X1" => [
      ini: [:e, :s],
      rsp: [:e, :ee, :s],
      ini: [:se, :es]
    ]
  }

  @spec fetch!(String.t()) :: list()
  def fetch!(name), do: Map.fetch!(@handshakes, name)
end
