defmodule Decibel.MixProject do
  use Mix.Project

  @version "0.2.4"
  @source_url "https://github.com/ausimian/decibel"

  def project do
    [
      app: :decibel,
      version: System.get_env("VERSION_OVERRIDE", @version),
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      package: package(),
      source_url: @source_url,
      test_coverage: [tool: ExCoveralls],
      docs: [
        main: "Decibel",
        extras: ["CHANGELOG.md"],
        source_ref: @version,
        source_url: @source_url
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {Decibel.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:jason, "~> 1.0", only: [:dev, :test]},
      {:publisho, "~> 1.0", only: :dev, runtime: false},
      {:typedstruct, "~> 0.5.0", runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "credo --strict", "test"],
      release: ["deps.get", "compile", "release"]
    ]
  end

  defp package do
    [
      description: "An Elixir implementation of the Noise Protocol Framework.",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Noise Protocol Framework" => "https://noiseprotocol.org/index.html"
      }
    ]
  end
end
