defmodule Decibel.SessionKeyHeir do
  @moduledoc false

  @spec ensure_started() :: {:ok, pid()}
  def ensure_started do
    case Process.whereis(__MODULE__) do
      nil -> start_process()
      pid -> {:ok, pid}
    end
  end

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
        try do
          Process.group_leader(self(), Process.whereis(:init))
          Process.register(self(), __MODULE__)
          send(parent, {reference, :started, self()})
          loop()
        rescue
          ArgumentError -> send(parent, {reference, :already_started})
        end
      end)

    receive do
      {^reference, :started, ^pid} -> {:ok, pid}
      {^reference, :already_started} -> ensure_started()
    after
      5_000 -> exit({:timeout, {__MODULE__, :ensure_started}})
    end
  end
end
