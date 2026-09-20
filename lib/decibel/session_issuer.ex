defmodule Decibel.SessionIssuer do
  @moduledoc false

  use GenServer

  @spec start_link(term()) :: GenServer.on_start()
  def start_link(_options), do: GenServer.start_link(__MODULE__, :ok, name: __MODULE__)

  @spec issue() :: {reference(), reference(), binary()}
  def issue, do: issue(System.monotonic_time(:millisecond) + 5_000)

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
    secrets = :ets.new(__MODULE__, [:set, :private])
    send(self(), :recover_keypair)
    {:ok, secrets}
  end

  @impl true
  def handle_call(:issue, {owner, _tag}, secrets) do
    case lookup_keypair(secrets) do
      {:ok, keypair} ->
        id = make_ref()
        status = :atomics.new(1, signed: false)
        proof = proof(keypair, owner, id, status)
        {:reply, {id, status, proof}, secrets}

      :not_ready ->
        {:reply, :not_ready, secrets}
    end
  end

  def handle_call(:keypair, {caller, _tag}, secrets) do
    if caller == supervised_child(Decibel.SessionKeys) do
      {:reply, lookup_keypair(secrets), secrets}
    else
      {:reply, :error, secrets}
    end
  end

  @impl true
  def handle_info(:recover_keypair, secrets) do
    keys = supervised_child(Decibel.SessionKeys)

    case GenServer.call(keys, :keypair) do
      {:ok, keypair} ->
        :ets.insert(secrets, {:keypair, keypair})

      :not_ready ->
        Process.send_after(self(), :recover_keypair, 1)
    end

    {:noreply, secrets}
  end

  defp issue(deadline) do
    now = System.monotonic_time(:millisecond)

    case GenServer.call(__MODULE__, :issue) do
      :not_ready when now < deadline ->
        Process.sleep(1)
        issue(deadline)

      :not_ready ->
        exit({:timeout, {__MODULE__, :issue}})

      session_identity ->
        session_identity
    end
  end

  defp lookup_keypair(secrets) do
    case :ets.lookup(secrets, :keypair) do
      [{:keypair, keypair}] -> {:ok, keypair}
      [] -> :not_ready
    end
  end

  defp proof({_public_key, private_key}, owner, id, status) do
    data = proof_data(owner, id, status)
    :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])
  end

  defp proof_data(owner, id, status), do: :erlang.term_to_binary({owner, id, status})

  defp supervised_child(module) do
    case List.keyfind(Supervisor.which_children(Decibel.Supervisor), module, 0) do
      {^module, pid, :worker, _modules} when is_pid(pid) -> pid
      _other -> nil
    end
  end
end
