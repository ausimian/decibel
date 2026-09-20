# This module deliberately bypasses Decibel's ephemeral-key safety boundary.
# It exists only for known-answer vectors that require deterministic keypairs;
# reusing its inputs in real sessions can cause catastrophic key/nonce reuse.
# Nothing in Decibel's safe public API calls or depends on this module.
# Some known-answer vectors provide an ephemeral for a role that never sends an
# `e` token, such as a one-way responder. A valid but unused override is ignored.
defmodule Decibel.Unsafe do
  @moduledoc false

  alias Decibel.{Handshake, Session}

  @doc false
  @spec new(String.t(), Decibel.role(), Decibel.key_material(), keyword()) :: Decibel.session()
  def new(protocol_name, role, keys \\ %{}, opts \\ []) do
    protocol_name
    |> Handshake.initialize(role, keys, opts, :unsafe_test_ephemeral)
    |> Session.create()
  end
end
