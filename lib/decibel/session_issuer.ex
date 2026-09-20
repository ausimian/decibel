defmodule Decibel.SessionIssuer do
  @moduledoc false

  use GenServer

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(_options), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @spec issue() :: {reference(), reference(), binary()}
  def issue, do: GenServer.call(__MODULE__, :issue)

  @spec keypair() :: {:ok, {binary(), binary()}} | :error
  def keypair, do: GenServer.call(__MODULE__, :keypair)

  @spec issued?(pid(), reference(), reference(), binary()) :: boolean()
  def issued?(owner, id, status, proof)
      when is_pid(owner) and is_reference(id) and is_reference(status) and is_binary(proof) do
    case Decibel.SessionKeys.public_key() do
      {:ok, public_key} ->
        data = proof_data(owner, id, status)
        :crypto.verify(:eddsa, :none, data, proof, [public_key, :ed25519])

      _other ->
        false
    end
  rescue
    ArgumentError -> false
  end

  def issued?(_owner, _id, _status, _proof), do: false

  @impl true
  def init(:ok) do
    {:ok, keypair} = Decibel.SessionKeys.keypair()
    secrets = :ets.new(__MODULE__, [:set, :private])
    :ets.insert(secrets, {:keypair, keypair})
    {:ok, secrets}
  end

  @impl true
  def handle_call(:issue, {owner, _tag}, secrets) do
    id = make_ref()
    status = :atomics.new(1, signed: false)
    proof = proof(secrets, owner, id, status)
    {:reply, {id, status, proof}, secrets}
  end

  def handle_call(:keypair, {caller, _tag}, secrets) do
    if caller == Process.whereis(Decibel.SessionKeys) do
      {:reply, {:ok, :ets.lookup_element(secrets, :keypair, 2)}, secrets}
    else
      {:reply, :error, secrets}
    end
  end

  defp proof(secrets, owner, id, status) do
    {_public_key, private_key} = :ets.lookup_element(secrets, :keypair, 2)
    data = proof_data(owner, id, status)
    :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])
  end

  defp proof_data(owner, id, status), do: :erlang.term_to_binary({owner, id, status})
end
