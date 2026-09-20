defmodule Decibel.SessionKeys do
  @moduledoc false

  use GenServer

  @public_keys :decibel_session_public_keys

  @spec start_link(binary()) :: GenServer.on_start()
  def start_link(public_key), do: GenServer.start_link(__MODULE__, public_key, name: __MODULE__)

  @spec public_key() :: {:ok, binary()} | :error
  def public_key do
    case :ets.lookup(@public_keys, :public_key) do
      [{:public_key, public_key}] -> {:ok, public_key}
      _other -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @impl true
  def init(public_key) do
    table =
      :ets.new(@public_keys, [
        :named_table,
        :set,
        :protected,
        {:read_concurrency, true}
      ])

    :ets.insert(table, {:public_key, public_key})
    {:ok, table}
  end
end
