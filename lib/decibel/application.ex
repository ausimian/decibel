defmodule Decibel.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    {public_key, _private_key} = keypair = :crypto.generate_key(:eddsa, :ed25519)

    children = [
      {Decibel.SessionKeys, public_key},
      {Decibel.SessionIssuer, keypair}
    ]

    Supervisor.start_link(children, strategy: :rest_for_one, name: Decibel.Supervisor)
  end
end
