defmodule Decibel.ReplayWindowTest do
  use ExUnit.Case, async: true

  alias Decibel.ReplayWindow

  @max_nonce 18_446_744_073_709_551_614

  test "defaults to a 64-position window" do
    window = ReplayWindow.new()
    window = ReplayWindow.commit(window, 64)

    assert {:error, :stale} == ReplayWindow.check(window, 0)
    assert :ok == ReplayWindow.check(window, 1)
  end

  test "requires a positive integer size" do
    for invalid <- [0, -1, 1.5, nil, :large] do
      assert_raise ArgumentError, fn -> ReplayWindow.new(invalid) end
    end

    assert :ok == ReplayWindow.check(ReplayWindow.new(1), 0)
    assert :ok == ReplayWindow.check(ReplayWindow.new(7), 0)
  end

  test "accepts the first delivery and rejects its exact duplicate" do
    window = ReplayWindow.new(64)

    assert :ok == ReplayWindow.check(window, 0)
    window = ReplayWindow.commit(window, 0)
    assert {:error, :duplicate} == ReplayWindow.check(window, 0)

    assert_raise ArgumentError, "cannot commit duplicate nonce 0", fn ->
      ReplayWindow.commit(window, 0)
    end
  end

  test "accepts reordered delivery at the lower edge and rejects the first stale nonce" do
    window = ReplayWindow.new(64) |> ReplayWindow.commit(65)

    assert {:error, :duplicate} == ReplayWindow.check(window, 65)
    assert :ok == ReplayWindow.check(window, 2)
    assert {:error, :stale} == ReplayWindow.check(window, 1)

    window = ReplayWindow.commit(window, 2)
    assert {:error, :duplicate} == ReplayWindow.check(window, 2)

    assert_raise ArgumentError, "cannot commit stale nonce 1", fn ->
      ReplayWindow.commit(window, 1)
    end
  end

  test "slides without dropping or aliasing in-window bits" do
    window = ReplayWindow.new(4) |> ReplayWindow.commit(10) |> ReplayWindow.commit(7)

    assert {:error, :duplicate} == ReplayWindow.check(window, 10)
    assert {:error, :duplicate} == ReplayWindow.check(window, 7)
    assert :ok == ReplayWindow.check(window, 8)
    assert :ok == ReplayWindow.check(window, 9)

    window = ReplayWindow.commit(window, 11)

    assert {:error, :duplicate} == ReplayWindow.check(window, 11)
    assert {:error, :duplicate} == ReplayWindow.check(window, 10)
    assert :ok == ReplayWindow.check(window, 8)
    assert {:error, :stale} == ReplayWindow.check(window, 7)

    window = ReplayWindow.commit(window, 8) |> ReplayWindow.commit(12)

    assert {:error, :duplicate} == ReplayWindow.check(window, 12)
    assert {:error, :duplicate} == ReplayWindow.check(window, 11)
    assert {:error, :duplicate} == ReplayWindow.check(window, 10)
    assert {:error, :stale} == ReplayWindow.check(window, 8)
    assert :ok == ReplayWindow.check(window, 9)
  end

  test "a jump of at least the size discards the complete bitmap" do
    window = ReplayWindow.new(4) |> ReplayWindow.commit(0) |> ReplayWindow.commit(3)
    assert {:error, :duplicate} == ReplayWindow.check(window, 0)

    window = ReplayWindow.commit(window, 7)
    assert {:error, :stale} == ReplayWindow.check(window, 3)
    assert :ok == ReplayWindow.check(window, 6)

    window = ReplayWindow.commit(window, 100)
    assert {:error, :stale} == ReplayWindow.check(window, 7)
    assert :ok == ReplayWindow.check(window, 99)

    window = ReplayWindow.commit(window, 99)
    assert {:error, :duplicate} == ReplayWindow.check(window, 99)
  end

  test "supports a one-position window and other non-default sizes" do
    one = ReplayWindow.new(1) |> ReplayWindow.commit(5)
    assert {:error, :duplicate} == ReplayWindow.check(one, 5)
    assert {:error, :stale} == ReplayWindow.check(one, 4)
    assert :ok == ReplayWindow.check(one, 6)

    one = ReplayWindow.commit(one, 6)
    assert {:error, :stale} == ReplayWindow.check(one, 5)

    seven = ReplayWindow.new(7) |> ReplayWindow.commit(20)
    assert :ok == ReplayWindow.check(seven, 14)
    assert {:error, :stale} == ReplayWindow.check(seven, 13)
  end

  test "handles the final usable nonce without overflow" do
    assert :ok == ReplayWindow.check(ReplayWindow.new(), @max_nonce)

    window = ReplayWindow.new(64) |> ReplayWindow.commit(@max_nonce - 64)
    assert :ok == ReplayWindow.check(window, @max_nonce)

    window = ReplayWindow.commit(window, @max_nonce)
    assert {:error, :duplicate} == ReplayWindow.check(window, @max_nonce)
    assert {:error, :stale} == ReplayWindow.check(window, @max_nonce - 64)
    assert :ok == ReplayWindow.check(window, @max_nonce - 63)

    window = ReplayWindow.commit(window, @max_nonce - 63)
    assert {:error, :duplicate} == ReplayWindow.check(window, @max_nonce - 63)
  end

  test "rejects values outside the usable nonce range consistently" do
    window = ReplayWindow.new()

    for invalid <- [-1, @max_nonce + 1, @max_nonce + 2, 1.0, nil, :nonce] do
      assert_raise ArgumentError, fn -> ReplayWindow.check(window, invalid) end
      assert_raise ArgumentError, fn -> ReplayWindow.commit(window, invalid) end
    end
  end

  test "check and commit agree exhaustively across representative window states" do
    for size <- [1, 2, 3, 7, 16, 64],
        window <- window_states(size),
        nonce <- 0..255 do
      case ReplayWindow.check(window, nonce) do
        :ok ->
          committed = ReplayWindow.commit(window, nonce)
          assert {:error, :duplicate} == ReplayWindow.check(committed, nonce)

        {:error, reason} when reason in [:duplicate, :stale] ->
          assert_raise ArgumentError, fn -> ReplayWindow.commit(window, nonce) end
      end
    end
  end

  defp window_states(size) do
    initial = ReplayWindow.new(size)

    states =
      Enum.scan([0, 1, 3, 2, 8, 5, 16, 15, 32, 30, 64, 63, 96, 95, 128, 127, 192, 191, 255], initial, fn
        nonce, window ->
          case ReplayWindow.check(window, nonce) do
            :ok -> ReplayWindow.commit(window, nonce)
            {:error, _reason} -> window
          end
      end)

    [initial | states]
  end
end
