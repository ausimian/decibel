# Upgrading to Decibel 1.0

Decibel 1.0 uses idiomatic accessor names:

- `is_handshake_complete?/1` becomes `handshake_complete?/1`.
- `get_handshake_hash/1` becomes `handshake_hash/1`.
- `get_nonce/2` becomes `nonce/2`.
- `get_remote_key/1` becomes `remote_key/1`.

The 0.2 names remain deprecated aliases for the 1.0 compatibility release
and are scheduled for removal in Decibel 2.0.

Sessions are now opaque `Decibel.Session` handles owned by the process that
creates them. They cannot be transferred between processes. Operations
return data or `:ok` directly and raise the stable exceptions described in
[API conventions](`m:Decibel#module-api-conventions`) on failure.

`:swap` is the only public construction option. Both peers must use the same
value; Noise Pipes fallback uses `swap: :rsp`. The former custom `:registry`
option is no longer supported because custom handshake patterns are outside
Decibel's supported and vector-tested protocol surface.
