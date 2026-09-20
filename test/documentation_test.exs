defmodule Decibel.DocumentationTest do
  use ExUnit.Case, async: true

  alias Decibel.{Registry, Utility}

  @project_root Path.expand("..", __DIR__)
  @readme_path Path.join(@project_root, "README.md")
  @published_documents [
                         @readme_path,
                         Path.join(@project_root, "CHANGELOG.md"),
                         Path.join(@project_root, "RELEASE.md"),
                         Path.join(@project_root, "SECURITY.md")
                       ] ++ Path.wildcard(Path.join(@project_root, "lib/**/*.ex"))
  @protocol_name ~r/\bNoise_(?:[A-Za-z0-9+\/]+_){3}[A-Za-z0-9+\/]+\b/

  # Deliberately rejected names shown in public documentation must be listed
  # here with a comment explaining the example. Do not weaken @protocol_name.
  @deliberately_invalid_protocol_names MapSet.new([])

  for example <- ~w(nn ik) do
    test "README #{String.upcase(example)} quickstart is runnable" do
      assert {:ok, _binding} =
               unquote(example)
               |> readme_example()
               |> Code.eval_string([], file: @readme_path)
    end
  end

  test "every documented protocol name is parser-valid and supported" do
    documented_names =
      Enum.reduce(@published_documents, MapSet.new(), fn path, names ->
        path
        |> File.read!()
        |> then(&Regex.scan(@protocol_name, &1, capture: :first))
        |> List.flatten()
        |> Enum.reduce(names, &MapSet.put(&2, &1))
      end)

    assert MapSet.size(documented_names) > 0
    assert MapSet.subset?(@deliberately_invalid_protocol_names, documented_names)

    for protocol <- MapSet.difference(documented_names, @deliberately_invalid_protocol_names) do
      {{pattern, modifiers}, _curve, _cipher, _hash} = Utility.parse_protocol_name(protocol)

      pattern
      |> Registry.fetch!()
      |> Utility.split_handshake()
      |> Utility.modify_handshake(modifiers)
    end
  end

  test "the former Blake2b protocol spelling is rejected" do
    assert_raise ArgumentError, ~r/unsupported hash function "Blake2b"/, fn ->
      Utility.parse_protocol_name("Noise_XXfallback_25519_ChaChaPoly_Blake2b")
    end
  end

  defp readme_example(name) do
    escaped_name = Regex.escape(name)

    pattern =
      Regex.compile!(
        "<!-- quickstart:#{escaped_name}:start -->\\s*```elixir\\n(?<code>.*?)\\n```\\s*" <>
          "<!-- quickstart:#{escaped_name}:end -->",
        "s"
      )

    %{"code" => code} = Regex.named_captures(pattern, File.read!(@readme_path))
    code
  end
end
