defmodule Decibel.VectorCorpus do
  @moduledoc false

  @root Path.expand("..", __DIR__)

  @vectors [
    %{
      file: "cacophony.json",
      url:
        "https://raw.githubusercontent.com/haskell-cryptography/cacophony/" <>
          "18b7348c54fd61fcd0c220298883de0d09c8364d/vectors/cacophony.txt",
      source_sha256: "3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae",
      checked_sha256: "3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae",
      transform: :copy
    },
    %{
      file: "cacophony-psk.json",
      url:
        "https://raw.githubusercontent.com/haskell-cryptography/cacophony/" <>
          "8f6c53a575a7843eb175d04dbee9fb963ecf45aa/vectors/cacophony.txt",
      source_sha256: "c1a7f575600ae77d86321d5eb99aad8598e9f23df6b0d700b01aeeb6fa5690c2",
      checked_sha256: "c1a7f575600ae77d86321d5eb99aad8598e9f23df6b0d700b01aeeb6fa5690c2",
      transform: :copy
    },
    %{
      file: "snow.json",
      url:
        "https://raw.githubusercontent.com/mcginty/snow/" <>
          "33934b7e3d9ec1377fc1b5eac0fe7a103b6f506b/tests/vectors/snow.txt",
      source_sha256: "233c347e8c92560b30ba49835a2361e1bd6a74e7364741378b298f47602fc508",
      checked_sha256: "233c347e8c92560b30ba49835a2361e1bd6a74e7364741378b298f47602fc508",
      transform: :copy
    },
    %{
      file: "noise-c-fallback.json",
      url:
        "https://raw.githubusercontent.com/rweather/noise-c/" <>
          "ec5de2ca65b093234c82c45f47b46d19bfa912e4/tests/vector/noise-c-fallback.txt",
      source_sha256: "b6e110fd4edfb30d35336d7eeb4c9fc71fc810b39d1a3745fe7ef14b874a0370",
      checked_sha256: "1d4ae14c7ab1b576600e468114cc0374e96e227608552563c8ab9c66cce2d57c",
      transform: :indent_four
    }
  ]

  def run(["verify"]) do
    Enum.each(@vectors, &verify_checked_file!/1)
  end

  def run(["update"]) do
    curl = System.find_executable("curl") || abort!("curl is required to update vector corpora")

    prepared =
      Enum.map(@vectors, fn vector ->
        source = download!(curl, vector)
        verify_checksum!(source, vector.source_sha256, "downloaded source for #{vector.file}")

        checked = transform(source, vector.transform)
        verify_checksum!(checked, vector.checked_sha256, "transformed output for #{vector.file}")
        {vector, checked}
      end)

    Enum.each(prepared, fn {vector, bytes} -> write_atomically!(vector, bytes) end)
    Enum.each(@vectors, &verify_checked_file!/1)
  end

  def run(_arguments) do
    abort!("usage: elixir scripts/vectors.exs verify|update", 2)
  end

  defp verify_checked_file!(vector) do
    path = destination(vector)
    verify_checksum!(File.read!(path), vector.checked_sha256, path)
    IO.puts("verified #{vector.file} #{vector.checked_sha256}")
  end

  defp download!(curl, vector) do
    case System.cmd(curl, ["--fail", "--location", "--silent", "--show-error", vector.url], stderr_to_stdout: true) do
      {bytes, 0} -> bytes
      {output, status} -> abort!("download failed for #{vector.file} (exit #{status}): #{String.trim(output)}")
    end
  end

  defp transform(source, :copy), do: source

  defp transform(source, :indent_four) do
    {lines, 0} =
      source
      |> String.split("\n", trim: true)
      |> Enum.map_reduce(0, fn source_line, depth ->
        line = String.trim(source_line)
        depth = if String.starts_with?(line, ["}", "]"]), do: depth - 1, else: depth
        rendered = String.duplicate("    ", depth) <> line
        depth = if String.ends_with?(line, ["{", "["]), do: depth + 1, else: depth
        {rendered, depth}
      end)

    Enum.join(lines, "\n")
  end

  defp write_atomically!(vector, bytes) do
    destination = destination(vector)
    temporary = destination <> ".tmp-#{System.unique_integer([:positive])}"

    try do
      File.write!(temporary, bytes, [:binary, :exclusive])
      verify_checksum!(File.read!(temporary), vector.checked_sha256, temporary)
      File.rename!(temporary, destination)
      IO.puts("updated #{vector.file}")
    after
      if File.exists?(temporary), do: File.rm!(temporary)
    end
  end

  defp destination(vector), do: Path.join([@root, "test", "vectors", vector.file])

  defp verify_checksum!(bytes, expected, description) do
    actual = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

    if actual != expected do
      abort!("SHA-256 mismatch for #{description}: expected #{expected}, got #{actual}")
    end
  end

  defp abort!(message, status \\ 1) do
    IO.puts(:stderr, message)
    System.halt(status)
  end
end

Decibel.VectorCorpus.run(System.argv())
