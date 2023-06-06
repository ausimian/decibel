defmodule Decibel.MixProject do
  use Mix.Project

  def project do
    [
      app: :decibel,
      version: "0.2.3",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      source_url: "https://github.com/ausimian/decibel",
      docs: [
        main: "Decibel",
        extras: ["CHANGELOG.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:credo, ">= 0.0.0", only: [:dev], runtime: false},
      {:dialyxir, ">= 0.0.0", only: [:dev], runtime: false},
      {:doctor, ">= 0.0.0", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false},
      {:ex_check, "~> 0.14.0", only: [:dev], runtime: false},
      {:jason, "~> 1.0", only: [:dev, :test]},
      {:typed_struct, "~> 0.3.0", runtime: false}
    ]
  end

  defp package do
    [
      description: "An Elixir implementation of the Noise Protocol Framework.",
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/ausimian/decibel",
        "Noise Protocol Framework" => "https://noiseprotocol.org/index.html"
      }
    ]
  end
end
