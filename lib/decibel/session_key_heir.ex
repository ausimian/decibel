defmodule Decibel.SessionKeyHeir do
  @moduledoc false

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
  def start_link(_options), do: start_process(&loop/0)

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
