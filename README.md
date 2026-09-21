# Decibel

Decibel is an Elixir implementation of the
[Noise Protocol Framework](https://noiseprotocol.org/).

Decibel has not received an independent security audit or formal verification
and has not been declared production-ready. Review the complete
[security guidance](https://hexdocs.pm/decibel/security.html) before
integrating it.

## Documentation

- [Getting Started](https://hexdocs.pm/decibel/getting-started.html)
- [Security](https://hexdocs.pm/decibel/security.html)
- [Connectionless Transports](https://hexdocs.pm/decibel/connectionless-transports.html)
- [Noise Pipes](https://hexdocs.pm/decibel/noise-pipes.html)
- [Upgrading to Decibel 1.0](https://hexdocs.pm/decibel/upgrading-to-1-0.html)
- [Changelog](https://hexdocs.pm/decibel/changelog.html)
- [Security Policy](https://github.com/ausimian/decibel/blob/main/SECURITY.md)

## Development

Run `mix precommit` before committing. Release-focused CI also requires
warning-free Dialyzer and ExDoc runs, an exact Hex package manifest, clean Hex
dependency audits, and at least 97% total line coverage;
`MIX_ENV=test mix coveralls` exits non-zero below that floor.
