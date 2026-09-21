# Decibel

Decibel is an Elixir implementation of the
[Noise Protocol Framework](https://noiseprotocol.org/).

Decibel has not received an independent security audit or formal verification
and has not been declared production-ready. Review the complete
[security guidance](guides/security.md) before integrating it.

## Documentation

- [Getting Started](guides/getting-started.md)
- [Security](guides/security.md)
- [Connectionless Transports](guides/connectionless-transports.md)
- [Noise Pipes](guides/noise-pipes.md)
- [Upgrading to Decibel 1.0](guides/upgrading-to-1.0.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)

## Development

Run `mix precommit` before committing. Release-focused CI also requires
warning-free Dialyzer and ExDoc runs, an exact Hex package manifest, clean Hex
dependency audits, and at least 97% total line coverage;
`MIX_ENV=test mix coveralls` exits non-zero below that floor.
