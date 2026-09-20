defmodule Decibel.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    generation = make_ref()

    children = [
      {Decibel.SessionKeyHeir, generation},
      {Decibel.SessionKeys, generation}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Decibel.Supervisor)
  end
end
