# Test vector provenance

Decibel's known-answer vectors are immutable snapshots of upstream corpora. The
normal test suite reads only these checked-in files and never accesses the
network.

Verify every checked-in SHA-256 offline from the repository root:

```console
elixir scripts/vectors.exs verify
```

Explicitly download the pinned upstream revisions and reproduce the checked-in
files:

```console
elixir scripts/vectors.exs update
```

`update` is the only networked operation. It requires `curl`, checks the
downloaded source before applying any transformation, checks the transformed
result, and replaces each destination atomically from a same-directory temporary
file. A checksum mismatch never replaces a checked-in vector.

## Pinned corpora

| Checked-in file | Upstream source | Revision | Licence at revision | Upstream SHA-256 | Checked-in SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `cacophony.json` | [Cacophony `vectors/cacophony.txt`](https://github.com/haskell-cryptography/cacophony/blob/18b7348c54fd61fcd0c220298883de0d09c8364d/vectors/cacophony.txt) | `18b7348c54fd61fcd0c220298883de0d09c8364d` | [Unlicense](https://github.com/haskell-cryptography/cacophony/blob/18b7348c54fd61fcd0c220298883de0d09c8364d/LICENSE) | `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae` | `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae` |
| `cacophony-psk.json` | [Cacophony `vectors/cacophony.txt`](https://github.com/haskell-cryptography/cacophony/blob/8f6c53a575a7843eb175d04dbee9fb963ecf45aa/vectors/cacophony.txt) | `8f6c53a575a7843eb175d04dbee9fb963ecf45aa` | [Unlicense](https://github.com/haskell-cryptography/cacophony/blob/8f6c53a575a7843eb175d04dbee9fb963ecf45aa/LICENSE) | `c1a7f575600ae77d86321d5eb99aad8598e9f23df6b0d700b01aeeb6fa5690c2` | `c1a7f575600ae77d86321d5eb99aad8598e9f23df6b0d700b01aeeb6fa5690c2` |
| `snow.json` | [Snow `tests/vectors/snow.txt`](https://github.com/mcginty/snow/blob/33934b7e3d9ec1377fc1b5eac0fe7a103b6f506b/tests/vectors/snow.txt) | `33934b7e3d9ec1377fc1b5eac0fe7a103b6f506b` | [Unlicense](https://github.com/mcginty/snow/blob/33934b7e3d9ec1377fc1b5eac0fe7a103b6f506b/LICENSE) | `233c347e8c92560b30ba49835a2361e1bd6a74e7364741378b298f47602fc508` | `233c347e8c92560b30ba49835a2361e1bd6a74e7364741378b298f47602fc508` |
| `noise-c-fallback.json` | [noise-c `tests/vector/noise-c-fallback.txt`](https://github.com/rweather/noise-c/blob/ec5de2ca65b093234c82c45f47b46d19bfa912e4/tests/vector/noise-c-fallback.txt) | `ec5de2ca65b093234c82c45f47b46d19bfa912e4` | [MIT](https://github.com/rweather/noise-c/blob/ec5de2ca65b093234c82c45f47b46d19bfa912e4/COPYING) | `b6e110fd4edfb30d35336d7eeb4c9fc71fc810b39d1a3745fe7ef14b874a0370` | `1d4ae14c7ab1b576600e468114cc0374e96e227608552563c8ab9c66cce2d57c` |

The licence names above describe the named revision. In particular, the pinned
2019 Snow revision declares the Unlicense even though the current Snow
repository has different licence files.

## Transformations

- `cacophony.json` is a byte-for-byte copy. Only the local extension differs.
- `cacophony-psk.json` is a byte-for-byte copy of an older complete Cacophony
  corpus from before deferred patterns were added. It is not a locally filtered
  PSK-only file; only the local name and extension differ.
- `snow.json` is a byte-for-byte copy. Only the local extension differs.
- `noise-c-fallback.json` preserves all upstream keys, arrays, values, and their
  order. The update script applies four-space JSON indentation and omits the
  terminal newline; it performs no semantic transformation.

## Adversarial state-machine test configuration

`test/adversarial_state_machine_test.exs` runs its complete finite protocol and
primitive matrix once by default. It prints its seed and run count so CI failures
can be reproduced from the log alone. Set `DECIBEL_STATE_MACHINE_SEED` to a
non-negative integer to select the generated data and
`DECIBEL_STATE_MACHINE_RUNS` to a positive integer to repeat every matrix cell
with additional generated variants.
