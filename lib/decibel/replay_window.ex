defmodule Decibel.ReplayWindow do
  @moduledoc """
  An immutable replay window for connectionless transports.

  Applications own this value and store it alongside their session. Check an
  incoming nonce before authentication with `check/2`, then replace the stored
  window with the result of `commit/2` only after `Decibel.decrypt/3` succeeds.
  The module holds no process, ETS, or hidden session state.

  A window of size `size` retains exactly `size` nonce positions. After the
  first commit, those positions run from `highest` down to
  `highest - size + 1`; `highest - size` is the first stale value. Internally,
  bit `i` in the bitmap records nonce `highest - i`.

  Applications must serialize session operations with updates to their replay
  window. Sharing an old value between concurrent operations can allow both to
  pass `check/2` before either commits.
  """

  import Bitwise

  @default_size 64
  @max_nonce 18_446_744_073_709_551_614

  @enforce_keys [:size]
  defstruct [:size, highest: nil, bitmap: 0]

  @opaque t :: %__MODULE__{
            size: pos_integer(),
            highest: Decibel.usable_nonce() | nil,
            bitmap: non_neg_integer()
          }

  @doc """
  Creates an empty replay window.

  The default window size is 64. An explicit size must be a positive integer;
  invalid sizes raise `ArgumentError`.
  """
  @spec new(pos_integer()) :: t()
  def new(size \\ @default_size)

  def new(size) when is_integer(size) and size > 0 do
    %__MODULE__{size: size}
  end

  def new(size) do
    raise ArgumentError, "window size must be a positive integer, got: #{inspect(size)}"
  end

  @doc """
  Checks whether `nonce` is eligible for authentication.

  Returns `:ok` for a new nonce, `{:error, :duplicate}` for an already
  committed nonce still inside the window, or `{:error, :stale}` for a nonce
  below the window. The window is not changed.

  A value outside `t:Decibel.usable_nonce/0` raises `ArgumentError`.
  """
  @spec check(t(), Decibel.usable_nonce()) :: :ok | {:error, :duplicate | :stale}
  def check(%__MODULE__{} = window, nonce), do: classify(window, nonce)

  @doc """
  Commits a nonce after successful authentication.

  Returns a new window. A nonce that `check/2` classifies as duplicate or stale
  raises `ArgumentError`, because committing it indicates a caller error. A
  value outside `t:Decibel.usable_nonce/0` also raises `ArgumentError`.
  """
  @spec commit(t(), Decibel.usable_nonce()) :: t()
  def commit(%__MODULE__{} = window, nonce) do
    case classify(window, nonce) do
      :ok -> do_commit(window, nonce)
      {:error, reason} -> raise ArgumentError, "cannot commit #{reason} nonce #{nonce}"
    end
  end

  defp classify(window, nonce) do
    validate_nonce!(nonce)
    do_classify(window, nonce)
  end

  defp do_classify(%__MODULE__{highest: nil}, _nonce), do: :ok

  defp do_classify(%__MODULE__{highest: highest}, nonce) when nonce > highest,
    do: :ok

  defp do_classify(%__MODULE__{size: size, highest: highest, bitmap: bitmap}, nonce) do
    distance = highest - nonce

    cond do
      distance >= size -> {:error, :stale}
      (bitmap &&& 1 <<< distance) != 0 -> {:error, :duplicate}
      true -> :ok
    end
  end

  defp do_commit(%__MODULE__{highest: nil} = window, nonce) do
    %__MODULE__{window | highest: nonce, bitmap: 1}
  end

  defp do_commit(%__MODULE__{size: size, highest: highest} = window, nonce) when nonce > highest do
    delta = nonce - highest

    bitmap =
      if delta >= size do
        1
      else
        shifted = window.bitmap <<< delta ||| 1
        trim(shifted, size)
      end

    %__MODULE__{window | highest: nonce, bitmap: bitmap}
  end

  defp do_commit(%__MODULE__{highest: highest, bitmap: bitmap} = window, nonce) do
    %__MODULE__{window | bitmap: bitmap ||| 1 <<< (highest - nonce)}
  end

  defp trim(bitmap, size) do
    if bitmap >>> size == 0 do
      bitmap
    else
      bitmap &&& (1 <<< size) - 1
    end
  end

  defp validate_nonce!(nonce) when is_integer(nonce) and nonce >= 0 and nonce <= @max_nonce,
    do: nonce

  defp validate_nonce!(nonce) do
    raise ArgumentError,
          "nonce must be an integer from 0 to #{@max_nonce}, got: " <>
            inspect(nonce, limit: 10, printable_limit: 50)
  end
end
