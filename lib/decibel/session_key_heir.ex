defmodule Decibel.SessionKeyHeir do
  @moduledoc false

  @public_keys :decibel_session_public_keys

  @spec child_spec(reference()) :: Supervisor.child_spec()
  def child_spec(generation) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [generation]},
      type: :worker,
      restart: :permanent
    }
  end

  @spec start_link(reference()) :: {:ok, pid()} | {:error, term()}
  def start_link(generation) do
    parent = self()
    reference = make_ref()

    pid =
      spawn_link(fn ->
        Process.register(self(), __MODULE__)
        init(parent, reference, generation)
      end)

    receive do
      {^reference, :started, ^pid} -> {:ok, pid}
      {^reference, :error, reason} -> {:error, reason}
      {:EXIT, ^pid, reason} -> {:error, reason}
    after
      5_000 -> {:error, :start_timeout}
    end
  end

  defp init(parent, reference, generation) do
    Process.flag(:sensitive, true)

    case initialize_tables(generation) do
      {:ok, tables} ->
        send(parent, {reference, :started, self()})
        receive_loop(tables)

      {:error, reason} ->
        send(parent, {reference, :error, reason})
        exit(reason)
    end
  end

  defp initialize_tables(generation) do
    case :ets.whereis(@public_keys) do
      :undefined -> {:ok, create_tables(generation)}
      public -> validate_existing_owner(public)
    end
  end

  defp create_tables(generation) do
    keypair = {public_key, _private_key} = :crypto.generate_key(:eddsa, :ed25519)

    public =
      :ets.new(@public_keys, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true}
      ])

    secrets = :ets.new(Decibel.SessionKeys, [:set, :private])
    :ets.insert(public, [{:public_key, public_key}, {:generation, generation}])
    :ets.insert(secrets, {:keypair, keypair})
    %{public: public, secrets: secrets}
  end

  defp validate_existing_owner(public) do
    if :ets.info(public, :owner) == Process.whereis(Decibel.SessionKeys) do
      {:ok, %{}}
    else
      {:error, :untrusted_session_key_table}
    end
  end

  defp receive_loop(tables) do
    receive do
      {:"ETS-TRANSFER", table, _previous_owner, kind} when kind in [:public, :secrets] ->
        receive_loop(Map.put(tables, kind, table))

      {:reclaim, caller, reference} ->
        if caller == supervised_session_keys() and Map.has_key?(tables, :public) and
             Map.has_key?(tables, :secrets) do
          :ets.give_away(tables.public, caller, :public)
          :ets.give_away(tables.secrets, caller, :secrets)
          send(caller, {reference, {:ok, tables.public, tables.secrets}})
          receive_loop(%{})
        else
          send(caller, {reference, :error})
          receive_loop(tables)
        end

      _other ->
        receive_loop(tables)
    end
  end

  defp supervised_session_keys do
    case List.keyfind(Supervisor.which_children(Decibel.Supervisor), Decibel.SessionKeys, 0) do
      {Decibel.SessionKeys, pid, :worker, _modules} when is_pid(pid) -> pid
      _other -> nil
    end
  catch
    :exit, _reason -> nil
  end
end
