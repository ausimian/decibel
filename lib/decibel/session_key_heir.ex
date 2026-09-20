defmodule Decibel.SessionKeyHeir do
  @moduledoc false

  @public_keys :decibel_session_public_keys

  @spec ensure_started() :: {:ok, pid()}
  def ensure_started do
    case :ets.whereis(@public_keys) do
      :undefined ->
        start()

      public ->
        owner = :ets.info(public, :owner)

        if is_pid(owner) and Process.alive?(owner) do
          {:ok, owner}
        else
          start()
        end
    end
  end

  @spec start() :: {:ok, pid()}
  def start, do: start_process()

  defp loop do
    Process.flag(:sensitive, true)
    receive_loop(%{})
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
  end

  defp start_process do
    parent = self()
    reference = make_ref()

    pid =
      spawn(fn ->
        Process.group_leader(self(), Process.whereis(:init))
        send(parent, {reference, :started, self()})
        loop()
      end)

    receive do
      {^reference, :started, ^pid} -> {:ok, pid}
    after
      5_000 -> exit({:timeout, {__MODULE__, :ensure_started}})
    end
  end
end
