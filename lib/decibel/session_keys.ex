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

  @spec start_link(reference()) :: {:ok, pid()} | {:error, term()}
  def start_link(generation), do: start_process(&init(&1, generation))

  @spec issue() :: {reference(), reference(), reference(), binary()}
  def issue, do: call(:issue)

  @spec issued?(pid(), reference(), reference(), reference(), binary()) :: boolean()
  def issued?(owner, id, status, generation, proof)
      when is_pid(owner) and is_reference(id) and is_reference(status) and
             is_reference(generation) and is_binary(proof) do
    case public_key(generation) do
      {:ok, public_key} ->
        data = proof_data(owner, id, status, generation)
        :crypto.verify(:eddsa, :none, data, proof, [public_key, :ed25519])

      :error ->
        false
    end
  rescue
    ArgumentError -> false
  end

  def issued?(_owner, _id, _status, _generation, _proof), do: false

  @spec active_generation?(reference()) :: boolean()
  def active_generation?(generation) when is_reference(generation) do
    application_started?() and
      :ets.lookup(@public_keys, :generation) == [{:generation, generation}]
  rescue
    ArgumentError -> false
  end

  def active_generation?(_generation), do: false

  defp public_key(generation) do
    if active_generation?(generation) do
      case :ets.lookup(@public_keys, :public_key) do
        [{:public_key, public_key}] -> {:ok, public_key}
        _other -> :error
      end
    else
      :error
    end
  rescue
    ArgumentError -> :error
  end

  defp application_started? do
    Enum.any?(Application.started_applications(), fn
      {:decibel, _description, _version} -> true
      _other -> false
    end)
  end

  defp init(supervisor, generation) do
    Process.flag(:sensitive, true)
    Process.flag(:trap_exit, true)
    send(self(), :initialize)
    receive_loop(nil, supervisor, generation)
  end

  defp receive_loop(tables, supervisor, generation) do
    receive do
      :initialize ->
        receive_loop(initialize_tables(generation), supervisor, generation)

      {:issue, caller, reference} when not is_nil(tables) ->
        {_public_key, private_key} = :ets.lookup_element(tables.secrets, :keypair, 2)
        id = make_ref()
        status = :atomics.new(1, signed: false)
        data = proof_data(caller, id, status, generation)
        proof = :crypto.sign(:eddsa, :none, data, [private_key, :ed25519])
        send(caller, {reference, {id, status, generation, proof}})
        receive_loop(tables, supervisor, generation)

      {:issue, caller, reference} ->
        send(caller, {reference, :not_ready})
        receive_loop(tables, supervisor, generation)

      {:DOWN, monitor, :process, heir, _reason}
      when not is_nil(tables) and monitor == tables.heir_monitor and heir == tables.heir ->
        rebound = rebind_heir(%{tables | heir: nil, heir_monitor: nil})
        receive_loop(rebound, supervisor, generation)

      {:EXIT, ^supervisor, reason} ->
        exit(reason)

      {:EXIT, _other, _reason} ->
        receive_loop(tables, supervisor, generation)

      _other ->
        receive_loop(tables, supervisor, generation)
    end
  end

  defp rebind_heir(tables) do
    case supervised_key_heir() do
      heir when is_pid(heir) ->
        :ets.setopts(tables.public, {:heir, heir, :public})
        :ets.setopts(tables.secrets, {:heir, heir, :secrets})
        monitor = Process.monitor(heir)
        %{tables | heir: heir, heir_monitor: monitor}

      nil ->
        Process.sleep(1)
        rebind_heir(tables)
    end
  rescue
    ArgumentError -> exit(:session_key_tables_lost)
  end

  defp initialize_tables(generation) do
    case supervised_key_heir() do
      heir when is_pid(heir) ->
        reclaim_tables(heir, generation)

      nil ->
        Process.sleep(1)
        initialize_tables(generation)
    end
  end

  defp reclaim_tables(heir, generation) do
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

        unless :ets.lookup(public, :generation) == [{:generation, generation}] do
          exit(:session_key_generation_mismatch)
        end

        monitor = Process.monitor(heir)
        %{public: public, secrets: secrets, heir: heir, heir_monitor: monitor}

      {^reference, :error} ->
        Process.sleep(1)
        reclaim_tables(heir, generation)
    after
      5_000 -> exit(:reclaim_timeout)
    end
  end

  defp supervised_key_heir do
    case List.keyfind(Supervisor.which_children(Decibel.Supervisor), SessionKeyHeir, 0) do
      {SessionKeyHeir, pid, :worker, _modules} when is_pid(pid) -> pid
      _other -> nil
    end
  catch
    :exit, _reason -> nil
  end

  defp call(request), do: call(request, System.monotonic_time(:millisecond) + 5_000)

  defp call(request, deadline) do
    case Process.whereis(__MODULE__) do
      nil ->
        retry_call(request, deadline)

      server ->
        reference = make_ref()
        monitor = Process.monitor(server)
        send(server, {request, self(), reference})

        receive do
          {^reference, :not_ready} ->
            Process.demonitor(monitor, [:flush])
            retry_call(request, deadline)

          {^reference, response} ->
            Process.demonitor(monitor, [:flush])
            response

          {:DOWN, ^monitor, :process, ^server, _reason} ->
            retry_call(request, deadline)
        after
          max(deadline - System.monotonic_time(:millisecond), 0) ->
            Process.demonitor(monitor, [:flush])
            exit({:timeout, {__MODULE__, request}})
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

  defp proof_data(owner, id, status, generation),
    do: :erlang.term_to_binary({owner, id, status, generation})

  defp start_process(run) do
    parent = self()
    reference = make_ref()

    pid =
      spawn_link(fn ->
        Process.register(self(), __MODULE__)
        send(parent, {reference, :started, self()})
        run.(parent)
      end)

    receive do
      {^reference, :started, ^pid} -> {:ok, pid}
      {:EXIT, ^pid, reason} -> {:error, reason}
    after
      5_000 -> {:error, :start_timeout}
    end
  end
end
