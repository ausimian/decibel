defmodule Decibel.SessionIssuer do
  @moduledoc false

  use GenServer

  @proof_size 32

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(_options), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @spec issue() :: {reference(), reference(), binary()}
  def issue, do: GenServer.call(__MODULE__, :issue)

  @spec issued?(pid(), reference(), reference(), binary()) :: boolean()
  def issued?(owner, id, status, proof) do
    GenServer.call(__MODULE__, {:issued?, owner, id, status, proof})
  end

  @impl true
  def init(:ok) do
    secrets = :ets.new(__MODULE__, [:set, :private])
    :ets.insert(secrets, {:key, :crypto.strong_rand_bytes(@proof_size)})
    {:ok, secrets}
  end

  @impl true
  def handle_call(:issue, {owner, _tag}, secrets) do
    id = make_ref()
    status = :atomics.new(1, signed: false)
    proof = proof(secrets, owner, id, status)
    {:reply, {id, status, proof}, secrets}
  end

  def handle_call({:issued?, owner, id, status, candidate}, _from, secrets)
      when is_pid(owner) and is_reference(id) and is_reference(status) and is_binary(candidate) do
    expected = proof(secrets, owner, id, status)

    issued? =
      byte_size(candidate) == byte_size(expected) and
        :crypto.hash_equals(candidate, expected)

    {:reply, issued?, secrets}
  end

  def handle_call({:issued?, _owner, _id, _status, _proof}, _from, secrets),
    do: {:reply, false, secrets}

  defp proof(secrets, owner, id, status) do
    key = :ets.lookup_element(secrets, :key, 2)
    data = :erlang.term_to_binary({owner, id, status})
    :crypto.mac(:hmac, :sha256, key, data)
  end
end
