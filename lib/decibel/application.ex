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

    case Supervisor.start_link(children, strategy: :one_for_one, name: Decibel.Supervisor) do
      {:ok, supervisor} ->
        Decibel.SessionKeys.activate_generation(generation)
        {:ok, supervisor, generation}

      error ->
        error
    end
  end

  @impl true
  def stop(generation) do
    Decibel.SessionKeys.deactivate_generation(generation)
    :ok
  end
end
