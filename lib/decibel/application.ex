defmodule Decibel.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    {:ok, key_heir} = Decibel.SessionKeyHeir.ensure_started()
    children = [{Decibel.SessionKeys, key_heir}]

    Supervisor.start_link(children, strategy: :one_for_one, name: Decibel.Supervisor)
  end
end
