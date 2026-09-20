defmodule Decibel.SessionIssuer do
  @moduledoc false

  use GenServer

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(keypair), do: GenServer.start_link(__MODULE__, keypair, name: __MODULE__)

  @spec issue() :: {reference(), reference(), binary()}
  def issue, do: GenServer.call(__MODULE__, :issue)

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
  def init({_public_key, private_key}) do
    secrets = :ets.new(__MODULE__, [:set, :private])
    :ets.insert(secrets, {:private_key, private_key})
    {:ok, secrets}
  end

  @impl true
  def handle_call(:issue, {owner, _tag}, secrets) do
    id = make_ref()
    status = :atomics.new(1, signed: false)
    proof = proof(secrets, owner, id, status)
    {:reply, {id, status, proof}, secrets}
  end

  defp proof(secrets, owner, id, status) do
    private_key = :ets.lookup_element(secrets, :private_key, 2)
    data = proof_data(owner, id, status)
    :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])
  end

  defp proof_data(owner, id, status), do: :erlang.term_to_binary({owner, id, status})
end
