defmodule Decibel.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Decibel.SessionKeyHeir,
      Decibel.SessionKeys
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Decibel.Supervisor)
  end
end
