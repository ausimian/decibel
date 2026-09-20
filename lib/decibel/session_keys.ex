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
    secrets = :ets.new(__MODULE__, [:set, :private])

    if is_nil(Process.whereis(Decibel.SessionIssuer)) do
      install_keypair(secrets, :crypto.generate_key(:eddsa, :ed25519))
    else
      send(self(), :recover_keypair)
    end

    {:ok, secrets}
  end

  @impl true
  def handle_call(:keypair, {caller, _tag}, secrets) do
    if caller == supervised_child(Decibel.SessionIssuer) do
      {:reply, lookup_keypair(secrets), secrets}
    else
      {:reply, :error, secrets}
    end
  end

  @impl true
  def handle_info(:recover_keypair, secrets) do
    issuer = supervised_child(Decibel.SessionIssuer)

    case GenServer.call(issuer, :keypair) do
      {:ok, keypair} ->
        install_keypair(secrets, keypair)

      :not_ready ->
        Process.send_after(self(), :recover_keypair, 1)
    end

    {:noreply, secrets}
  end

  defp install_keypair(secrets, {public_key, _private_key} = keypair) do
    :ets.insert(secrets, {:keypair, keypair})

    table =
      :ets.new(@public_keys, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true}
      ])

    :ets.insert(table, {:public_key, public_key})
  end

  defp lookup_keypair(secrets) do
    case :ets.lookup(secrets, :keypair) do
      [{:keypair, keypair}] -> {:ok, keypair}
      [] -> :not_ready
    end
  end

  defp supervised_child(module) do
    case List.keyfind(Supervisor.which_children(Decibel.Supervisor), module, 0) do
      {^module, pid, :worker, _modules} when is_pid(pid) -> pid
      _other -> nil
    end
  end
end
