defmodule Decibel.SessionKeys do
  @moduledoc false

  use GenServer

  @public_keys :decibel_session_public_keys

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(_options), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @spec keypair() :: {:ok, {binary(), binary()}} | :error
  def keypair, do: GenServer.call(__MODULE__, :keypair)

  @spec public_key() :: {:ok, binary()} | :error
  def public_key do
    case :ets.lookup(@public_keys, :public_key) do
      [{:public_key, public_key}] -> {:ok, public_key}
      _other -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @impl true
  def init(:ok) do
    {public_key, _private_key} = keypair = recover_or_generate_keypair()
    secrets = :ets.new(__MODULE__, [:set, :private])
    :ets.insert(secrets, {:keypair, keypair})

    table =
      :ets.new(@public_keys, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true}
      ])

    :ets.insert(table, {:public_key, public_key})
    {:ok, secrets}
  end

  @impl true
  def handle_call(:keypair, {caller, _tag}, secrets) do
    if caller == Process.whereis(Decibel.SessionIssuer) do
      {:reply, {:ok, :ets.lookup_element(secrets, :keypair, 2)}, secrets}
    else
      {:reply, :error, secrets}
    end
  end

  defp recover_or_generate_keypair do
    case Process.whereis(Decibel.SessionIssuer) do
      nil ->
        :crypto.generate_key(:eddsa, :ed25519)

      _issuer ->
        {:ok, keypair} = Decibel.SessionIssuer.keypair()
        keypair
    end
  end
end
