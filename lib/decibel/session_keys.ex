defmodule Decibel.SessionKeys do
  @moduledoc false

  alias Decibel.SessionKeyHeir

  @public_keys :decibel_session_public_keys

  @spec child_spec(term()) :: Supervisor.child_spec()
  def child_spec(options) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [options]},
      type: :worker,
      restart: :permanent
    }
  end

  @spec start_link(term()) :: {:ok, pid()} | {:error, term()}
  def start_link(_options), do: start_process(&init/0)

  @spec issue() :: {reference(), reference(), binary()}
  def issue, do: call(:issue)

  @spec issued?(pid(), reference(), reference(), binary()) :: boolean()
  def issued?(owner, id, status, proof)
      when is_pid(owner) and is_reference(id) and is_reference(status) and is_binary(proof) do
    case public_key() do
      {:ok, public_key} ->
        data = proof_data(owner, id, status)
        :crypto.verify(:eddsa, :none, data, proof, [public_key, :ed25519])

      :error ->
        false
    end
  rescue
    ArgumentError -> false
  end

  def issued?(_owner, _id, _status, _proof), do: false

  @spec public_key() :: {:ok, binary()} | :error
  def public_key do
    case :ets.lookup(@public_keys, :public_key) do
      [{:public_key, public_key}] -> {:ok, public_key}
      _other -> :error
    end
  rescue
    ArgumentError -> :error
  end

  defp init do
    Process.flag(:sensitive, true)
    send(self(), :initialize)
    receive_loop(nil)
  end

  defp receive_loop(tables) do
    receive do
      :initialize ->
        receive_loop(initialize_tables())

      {:issue, caller, reference} when not is_nil(tables) ->
        {_public_key, private_key} = :ets.lookup_element(tables.secrets, :keypair, 2)
        id = make_ref()
        status = :atomics.new(1, signed: false)
        data = proof_data(caller, id, status)
        proof = :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])
        send(caller, {reference, {id, status, proof}})
        receive_loop(tables)

      {:issue, caller, reference} ->
        send(caller, {reference, :not_ready})
        receive_loop(tables)

      _other ->
        receive_loop(tables)
    end
  end

  defp initialize_tables do
    heir = supervised_child(SessionKeyHeir)

    case :ets.whereis(@public_keys) do
      :undefined -> create_tables(heir)
      _public -> reclaim_tables(heir)
    end
  end

  defp create_tables(heir) do
    keypair = {public_key, _private_key} = :crypto.generate_key(:eddsa, :ed25519)

    public =
      :ets.new(@public_keys, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true},
        {:heir, heir, :public}
      ])

    secrets = :ets.new(__MODULE__, [:set, :private, {:heir, heir, :secrets}])
    :ets.insert(public, {:public_key, public_key})
    :ets.insert(secrets, {:keypair, keypair})
    %{public: public, secrets: secrets}
  end

  defp reclaim_tables(heir) do
    reference = make_ref()
    send(heir, {:reclaim, self(), reference})

    receive do
      {^reference, {:ok, public, secrets}} ->
        receive do
          {:"ETS-TRANSFER", ^public, ^heir, :public} -> :ok
        end

        receive do
          {:"ETS-TRANSFER", ^secrets, ^heir, :secrets} -> :ok
        end

        :ets.setopts(public, {:heir, heir, :public})
        :ets.setopts(secrets, {:heir, heir, :secrets})
        %{public: public, secrets: secrets}

      {^reference, :error} ->
        Process.sleep(1)
        reclaim_tables(heir)
    after
      5_000 -> exit(:reclaim_timeout)
    end
  end

  defp call(request), do: call(request, System.monotonic_time(:millisecond) + 5_000)

  defp call(request, deadline) do
    case Process.whereis(__MODULE__) do
      nil ->
        retry_call(request, deadline)

      server ->
        reference = make_ref()
        send(server, {request, self(), reference})

        receive do
          {^reference, :not_ready} -> retry_call(request, deadline)
          {^reference, response} -> response
        after
          5_000 -> exit({:timeout, {__MODULE__, request}})
        end
    end
  end

  defp retry_call(request, deadline) do
    if System.monotonic_time(:millisecond) < deadline do
      Process.sleep(1)
      call(request, deadline)
    else
      exit({:timeout, {__MODULE__, request}})
    end
  end

  defp proof_data(owner, id, status), do: :erlang.term_to_binary({owner, id, status})

  defp supervised_child(module) do
    case List.keyfind(Supervisor.which_children(Decibel.Supervisor), module, 0) do
      {^module, pid, :worker, _modules} when is_pid(pid) -> pid
      _other -> nil
    end
  end

  defp start_process(run) do
    parent = self()
    reference = make_ref()

    pid =
      spawn_link(fn ->
        Process.register(self(), __MODULE__)
        send(parent, {reference, :started, self()})
        run.()
      end)

    receive do
      {^reference, :started, ^pid} -> {:ok, pid}
      {:EXIT, ^pid, reason} -> {:error, reason}
    after
      5_000 -> {:error, :start_timeout}
    end
  end
end
