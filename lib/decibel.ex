defmodule Decibel do
  @moduledoc """
  `Decibel` is an implementation of [The Noise Protocol Framework](https://noiseprotocol.org).

  > Noise is a framework for building crypto protocols. Noise protocols support
  > mutual and optional authentication, identity hiding, forward secrecy, zero
  > round-trip encryption, and other advanced features.

  For more information about Noise, its rationale, supported protocols etc,
  please refer to [The Noise Specification](https://noiseprotocol.org/noise.html).

  The rest of this document assumes the reader is familiar with the above
  specification.

  ## Security posture

  Decibel implements [Noise revision 34](https://noiseprotocol.org/noise.html).
  Revision 34 is marked `official/unstable`; its
  [change log](https://noiseprotocol.org/noise.html#change-log) says that the
  unstable marking applies only to the new deferred patterns and that the rest
  of the document is considered stable.

  The built-in registry supports these handshake patterns:

  - One-way: `N`, `K`, and `X`.
  - Fundamental interactive: `NN`, `KN`, `NK`, `KK`, `NX`, `KX`, `XN`,
    `IN`, `XK`, `IK`, `XX`, and `IX`.
  - Deferred interactive: `NK1`, `NX1`, `X1N`, `X1K`, `XK1`, `X1K1`,
    `X1X`, `XX1`, `X1X1`, `K1N`, `K1K`, `KK1`, `K1K1`, `K1X`, `KX1`,
    `K1X1`, `I1N`, `I1K`, `IK1`, `I1K1`, `I1X`, `IX1`, and `I1X1`.

  Decibel also supports applicable `pskN` and `fallback` modifiers. Supported
  primitives are:

  - DH: `25519` (X25519) and `448` (X448).
  - Cipher: `ChaChaPoly` (ChaCha20-Poly1305) and `AESGCM` (AES-256-GCM).
  - Hash: `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`.

  Custom patterns supplied through the `:registry` option are outside this
  supported surface and are not covered by the built-in pattern claims or
  vector suite.

  The test suite exercises checked-in known-answer vectors sourced from
  [Cacophony](https://github.com/haskell-cryptography/cacophony),
  [Snow](https://github.com/mcginty/snow), and
  [noise-c](https://github.com/rweather/noise-c) fallback vectors. Passing
  these vectors demonstrates interoperability for the tested inputs; it is not
  a security audit or a guarantee about an application's surrounding protocol.

  The package declares Elixir `~> 1.18`. CI currently tests Elixir 1.18 with
  OTP 27, Elixir 1.19 with OTP 27 and 28, and Elixir 1.20 with OTP 27 through
  29 on Linux and macOS. Cryptographic operations use Erlang/OTP's `:crypto`
  application. Decibel has no pluggable crypto provider, so the implementation
  and availability of these primitives depend on the OTP installation.

  > #### Security review and production use {: .warning}
  >
  > Decibel has not received an independent security audit or formal
  > verification. It is pre-1.0 and has not been declared production-ready.
  > Applications considering production use must review Decibel and their
  > complete protocol, key management, failure policy, and deployment against
  > their own threat model.

  Decibel's non-goals include transport I/O, message framing, protocol
  negotiation, peer identity or trust policy, long-term key storage, secure
  memory erasure, application payload parsing or padding, and connectionless
  replay state.

  ## Safe use

  ### Pattern and primitive selection

  Select a handshake pattern whose
  [payload security properties](https://noiseprotocol.org/noise.html#payload-security-properties)
  match the application's authentication, identity-hiding, forward-secrecy, and
  latency requirements.

  Noise's
  [application responsibilities](https://noiseprotocol.org/noise.html#application-responsibilities)
  recommend `25519` for typical use and say `448` should be paired with a
  512-bit hash such as `SHA512` or `BLAKE2b`. The specification also limits
  [AESGCM data under one key](https://noiseprotocol.org/noise.html#security-considerations)
  to 2^56 bytes; choose another cipher or re-handshake before that bound could
  be reached.

  ### Authentication and key handling

  A pattern containing static keys proves possession only where that pattern's
  security properties say it does. The application must decide whether a
  remote static key is acceptable, for example through a certificate,
  configured allow list, pinning, or key continuity. See the specification's
  [authentication guidance](https://noiseprotocol.org/noise.html#security-considerations)
  and authenticate the value available through `get_remote_key/1`.

  The specification's
  [key-reuse rules](https://noiseprotocol.org/noise.html#security-considerations)
  require a Noise static keypair to stay within Noise and one hash algorithm.
  A PSK must likewise stay within Noise and one hash algorithm, and must be a
  secret value with 256 bits of entropy. Decibel verifies that each PSK is 32
  bytes, but cannot verify its entropy or provenance; passwords and
  low-entropy tokens are not suitable PSKs. For every reused secret, the
  protocol name must uniquely identify the handshake pattern and cryptographic
  operations performed with that key.

  Every ordinary handshake generates a fresh local ephemeral keypair when its
  outbound `e` token is processed. Caller-supplied `:e` and `:re` values are
  accepted only for their corresponding fallback pre-messages. That reuse is
  part of the same compound-protocol run and does not make ephemeral reuse
  between sessions safe. The r34
  [ephemeral-key rule](https://noiseprotocol.org/noise.html#security-considerations)
  warns that reuse is likely to cause catastrophic key reuse.

  ### Negotiation and rollback

  Decibel does not negotiate protocol names, versions, roles, or application
  capabilities. If peers communicate negotiation data before the handshake,
  include a canonical encoding of that context in the same `:prologue` at both
  peers, or authenticate it through an equivalent higher-level design. The r34
  [rollback guidance](https://noiseprotocol.org/noise.html#security-considerations)
  warns that negotiation not included in the prologue can permit downgrade
  attacks.

  ### Framing, payloads, and termination

  Each Decibel handshake or transport operation processes exactly one Noise
  message. The application must frame message boundaries and enforce the
  65,535-byte Noise message limit. It must also authenticate length or
  termination information inside its payload protocol so an attacker cannot
  silently truncate a transport stream. Noise's
  [application responsibilities](https://noiseprotocol.org/noise.html#application-responsibilities)
  discuss framing, truncation, extensible payloads, and padding.

  ### Nonces, replay protection, and rekeying

  Never encrypt two messages under the same key and nonce. Decibel increments
  outbound nonces, rejects outbound rewinds, and raises `Decibel.NonceError`
  at exhaustion. For connectionless transport, `set_nonce/3` selects an inbound
  nonce but does not provide replay protection. The application must retain a
  bounded replay window, reject every nonce that has already authenticated, and
  record a nonce only after successful decryption. See
  [Connectionless Transports](#module-connectionless-transports) for a complete
  example and the specification's
  [out-of-order transport guidance](https://noiseprotocol.org/noise.html#out-of-order-transport-messages).

  `rekey/2` changes one directional key without resetting its nonce. Peers must
  coordinate rekeying independently in each direction, preserve their nonce and
  replay state, and expect delayed packets under the old key to fail. Close the
  session and perform a new handshake after nonce exhaustion. See the
  specification's [rekey guidance](https://noiseprotocol.org/noise.html#rekey).

  ### Failure handling

  Abandon a failed handshake unless the application is deliberately executing
  a reviewed compound protocol such as Noise Pipes fallback. For a transport
  authentication failure, discard the message and choose explicitly whether
  the threat model calls for closing the session or continuing. The Noise
  [processing rules](https://noiseprotocol.org/noise.html#processing-rules)
  permit either transport policy; unauthenticated plaintext must never be used.
  Do not expose detailed failure distinctions to an untrusted peer.

  Invalid construction and message-size inputs raise `ArgumentError`. Malformed,
  truncated, unauthenticated, or invalid-key peer messages raise
  `Decibel.DecryptionError` without committing state. Nonce failures raise
  `Decibel.NonceError`, and operations on a discarded one-way direction raise
  `Decibel.TransportDirectionError`. Invalid session ownership, lifetime, and
  phase transitions raise `Decibel.SessionError` with a stable `:reason`.

  ## Overview
  Decibel encrypts and decrypts messages according to the Noise Protocol,
  and the client's selection of handshake and cryptographic primitives. It does
  _not_ act as a transport, nor does it say anything about how Noise messages
  should be transmitted between participants.

  Each party - either the _initiator_ (the party that starts the handshake) or
  _responder_ (the other party) - advances the handshake until it completes, at
  which point a secure channel is established. Interactive handshakes establish
  bidirectional transport. The one-way `N`, `K`, and `X` patterns permit only the
  initiator to encrypt and only the responder to decrypt transport messages.

  Decibel supports all the handshake patterns outlined in r34 of the specification
  including the fundamental patterns, deferred patterns and one-way patterns. It
  also supports pre-shared keys as outlined in the specification, and fallback
  handshakes for [Noise Pipes](http://www.noiseprotocol.org/noise.html#noise-pipes)
  support.

  ## Example

  Consider the following handshake defined in the Noise Protocol:
  ```text
  NN:
    -> e
    <- e, ee
  ```

  The parties agree on this handshake and its cryptographic parameters and
  express this in a _protocol name_, e.g. `Noise_NN_25519_AESGCM_SHA256`. The
  _initiator's_ code may look something like this:

  ```elixir
  # Create the protocol instance
  ini = Decibel.new("Noise_NN_25519_AESGCM_SHA256", :ini)
  # Perform the first stage of the handshake
  msg1 = Decibel.handshake_encrypt(ini)
  # Somehow send this message to the responder and get the response
  magically_send_msg(rsp_proc, msg1)
  msg2 = magically_recv_msg(rsp_proc)
  # Process the response through the second stage
  Decibel.handshake_decrypt(ini, msg2)
  # At this point, the 'NN' handshake has completed for the initiator
  # and regular messages may be sent and received
  msg3 = Decibel.encrypt(ini, "Hello, world")
  magically_send_msg(rsp_proc, msg3)
  ```
  The _responder's_ code may look something like this:

  ```elixir
  # Create the protocol instance
  rsp = Decibel.new("Noise_NN_25519_AESGCM_SHA256", :rsp)
  # Receive the first-stage message from the initiator
  msg1 = magically_recv_msg(ini_proc)
  # Process the message through the protocol
  Decibel.handshake_decrypt(rsp, msg1)
  # Send the second stage to the initiator
  msg2 = Decibel.handshake_encrypt(rsp)
  magically_send_msg(ini_proc, msg2)
  # At this point, the 'NN' handshake has completed for the responder
  # and regular messages may be sent and received
  msg3 = magically_recv_msg(ini_proc)
  "Hello, world" = Decibel.decrypt(rsp, msg3)
  ```

  ## Lifecycle

  ### Ownership and lifetime

  `new/4` returns an opaque `t:session/0` handle. The session state belongs to
  the process that calls `new/4` and is stored in that process until `close/1`
  is called or the owner process exits. A handle contains no cryptographic state
  and must not be inspected, altered, or constructed by callers.

  Every operation on a session must run serially in its owner process. Do not
  pass the handle to a task, worker, or peer process, and do not call it
  concurrently. Pass Noise messages and application data between processes
  instead. A `GenServer` or similar long-lived process can own a session and
  serialize all operations in its callbacks. If that process terminates, its
  supervisor must establish a new session; the old one cannot be recovered or
  transferred.

  Decibel does not support session ownership transfer. Using a structurally
  valid handle in another process raises `Decibel.SessionError` with
  `reason: :not_owner`, including when the owner has closed it or exited. This
  classification uses the handle's owner PID alone by design; Decibel has no
  handle registry, issuance proof, or signature. A legacy bare reference,
  malformed value, or unknown owner-local handle uses `reason: :unknown`. After
  `close/1`, every operation by the owner, including another close, uses
  `reason: :closed`.

  During a live handshake, only the operation for the next pattern message is
  permitted. `handshake_encrypt/2` requires the `:handshake_write` phase and
  `handshake_decrypt/2` requires `:handshake_read`. Transport and cipher-state
  operations require `:transport`. A phase-invalid call raises
  `Decibel.SessionError` with `reason: :wrong_phase`, the operation, and the
  expected and actual phases, without changing session state.

  ### Creation

  Each party begins by creating a new handshake, via `new/4`, specifying the
  [protocol name](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers),
  the role the party plays in the handshake (`:ini` for initiator, `:rsp` for
  responder), and optionally any pre-message keys.

  ```
  # In the IK handshake, the responder's public (static) key is known to the
  # initiator prior to the handshake.
  keys = %{s: {<<...>>, <<...>>}, rs: <<...>>}
  ini  = Decibel.new("Noise_IK_448_ChaChaPoly_BLAKE2b", :ini, keys)
  ```

  The result of `new/4` is an opaque owner-aware handle used for the rest of the
  session. It is valid only in the process that created it.

  ### Handshake

  During the handshake phase, the protocol is advanced by each party in turn. For
  initiators, this typically starts with calling `handshake_encrypt/2` and sending
  the result to the responder. In turn, the responder calls `handshake_decrypt/2`
  before typically encrypting its own handshake message and sending that to the
  initiator.

  This sequence continues until the handshake is complete. If the selected protocol
  is known at compile time, the parties can just assume its completion in the
  absence of an error (as in the example [above](#module-example)). Alternatively,
  each party can call `is_handshake_complete?/1` after each handshake
  encryption/decryption.

  Once the handshake is complete, a secure channel is established with the
  [properties](https://noiseprotocol.org/noise.html#payload-security-properties) of
  the selected protocol.

  Additionally, once the handshake is complete, a unique 'session-hash' is available
  via `get_handshake_hash/1` - see the [channel-binding](https://noiseprotocol.org/noise.html#channel-binding)
  section of the specification for more details.

  ### Session

  Once the handshake is complete, the parties use `encrypt/3` and `decrypt/3` to
  exchange 'application' messages between each other. Both functions provide for optional
  'associated authenticated data' to be specified, that provides message-integrity
  assurance for the application data.

  Interactive handshake patterns allow both parties to encrypt and decrypt
  transport messages. For the one-way `N`, `K`, and `X` patterns, only the
  initiator may encrypt and only the responder may decrypt. Reverse-direction
  transport and cipher-management operations raise
  `Decibel.TransportDirectionError` without changing session state.

  Each call encrypts or decrypts exactly one Noise transport message. Noise messages
  are limited to 65,535 bytes, so transport plaintexts are limited to 65,519 bytes
  after allowing for the 16-byte authentication tag. Applications must split and
  frame larger logical messages before passing them to Decibel.

  Each keyed channel may use nonces from `0` through `2^64 - 2`. Consuming the
  final nonce exhausts that channel; later encryption or decryption raises
  `Decibel.NonceError`. An exhausted channel cannot be revived by `rekey/2`,
  so the application must close it and establish a new session.

  When the application is finished with the session, each party should call
  `close/1` to discard its cryptographic state. Owner-process termination also
  discards the state automatically.

  ## Noise Pipes

  [Noise Pipes](http://www.noiseprotocol.org/noise.html#noise-pipes) are compound protocols
  combining:

  - A full handshake (e.g. `XX`)
  - A zero-RTT handshake (e.g. `IK`)
  - A fallback handshake (e.g. `XXfallback`)

  The specification provides more detail on Noise Pipes, as does the
  [Wiki](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors#noise-pipes).
  Decibel provides support for all these individual protocols and the necessary
  information to transition between a failed IK handshake and the fallback.
  The failed session and its replacement fallback session must be created and
  operated by the same owner process. Pass the failed ciphertext to that owner;
  do not pass its session handle to a separate fallback worker.

  ### Decryption Errors

  Malformed peer messages raise `Decibel.DecryptionError`. Its `:reason` field is
  the stable error contract: `:truncated` identifies an incomplete key field or
  authentication tag, `:authentication_failed` identifies failed AEAD
  verification, and `:invalid_public_key` identifies a peer DH key rejected by
  the selected curve. The exception message remains `"Decryption failed"` for
  every reason.

  During a handshake, the error's `:remote_keys` field contains any remote public
  keys processed up to the point of failure. Failed operations do not update the
  stored handshake state or advance a transport nonce.

  ### Example

  The following example shows a responder handling the decryption failure, and then
  transitioning to the fallback protocol, using the remote ephemeral key, via
  `Noise_XXfallback_25519_ChaChaPoly_Blake2b`.

  ```elixir
  # Process IK handshake message sent by the initiator
  try do
    _ = Decibel.handshake_decrypt(rsp, ciphertext)
    # Happy path continues here...
  rescue
    e in Decibel.DecryptionError ->
      # Grab the remote ephemeral key sent by the initiator during the failed
      # handshake
      re = e.remote_keys[:re]
      # Now construct the new responder for the fallback protocol
      rsp = Decibel.new(
        "Noise_XXfallback_25519_ChaChaPoly_BLAKE2b",
        :rsp,
        %{re: re, s: responder_static},
        swap: :rsp
      )
      # Start the new handshake (not shown) ...
  end
  ```

  Note that although the code reconstructs the responder, as the handshake is a fallback
  protocol, the code is _effectively_ the initiator, and will send the first message on
  this new handshake.

  The failed initiator's original ephemeral is the fallback pre-message input on both
  sides. The original initiator supplies its local keypair as `:e`; the responder shown
  above retrieves the public key from the error and supplies it as `:re`. These keys are
  prior transcript input and are not transmitted again by the fallback handshake.

  - The retrieval of the remote ephemeral (`re`) key from the error
  - The prepopulation of that key as `:re` in the responder's new handshake (other keys
    omitted for brevity)
  - The use of the `[swap: :rsp]` option - this is required to ensure the split cipher
    channels are correctly paired after the interactive fallback handshake. The
    `swap:` option affects only interactive handshakes; it never reverses the
    permitted direction of a one-way handshake.

  ## Connectionless Transports

  Once the handshake completes, Noise provides support for the encryption and decryption
  of messages over connectionless i.e. potentially _unordered_, potentially _lossy_
  transports, and Decibel honours this support. For one-way patterns, the sender
  uses only the outbound operations and the recipient uses only the inbound
  operations shown below.

  > #### Danger: replay and nonce reuse {: .warning}
  >
  > A recipient using `set_nonce/3` must track every nonce that decrypted
  > successfully and reject duplicates; otherwise an attacker can replay an
  > authenticated message. An outbound nonce must never be reused with the same
  > key. Decibel deliberately exposes a low-level nonce API and does not provide
  > a replay-protected decrypt today, so the application owns this replay state.

  The sender and recipient sessions stay in their respective owner processes.
  Transfer `{nonce, ciphertext, aad}` between processes or peers, not either
  session handle. Each owner must serialize its session operations with updates
  to its application-owned replay window.

  A sender reads the nonce that `encrypt/3` will consume and sends it alongside
  the ciphertext:

  ```elixir
  nonce = Decibel.get_nonce(sender, :out)
  ciphertext = Decibel.encrypt(sender, plaintext, aad)
  send(peer, {nonce, ciphertext})
  ```

  The recipient needs a bounded replay window. This example retains the latest
  64 nonce values. A nonce at the lower edge is accepted; older messages are
  rejected as stale even if they were never received, keeping memory bounded.

  ```elixir
  defmodule ConnectionlessReplayWindow do
    @moduledoc false
    @size 64
    @max_nonce 2 ** 64 - 2

    def new, do: %{highest: nil, seen: MapSet.new()}

    def decrypt(ref, nonce, ciphertext, aad, window) do
      :ok = validate_nonce(ref, nonce)

      cond do
        MapSet.member?(window.seen, nonce) ->
          {:error, :duplicate, window}

        stale?(window, nonce) ->
          {:error, :stale, window}

        true ->
          :ok = Decibel.set_nonce(ref, :in, nonce)

          try do
            plaintext = Decibel.decrypt(ref, ciphertext, aad)
            {:ok, plaintext, remember(window, nonce)}
          rescue
            error in Decibel.DecryptionError -> {:error, error, window}
          end
      end
    end

    defp validate_nonce(_ref, nonce)
         when is_integer(nonce) and nonce >= 0 and nonce <= @max_nonce,
         do: :ok

    defp validate_nonce(ref, nonce), do: Decibel.set_nonce(ref, :in, nonce)

    defp stale?(%{highest: nil}, _nonce), do: false
    defp stale?(%{highest: highest}, nonce), do: nonce <= highest - @size

    defp remember(window, nonce) do
      highest = max(window.highest || nonce, nonce)

      seen =
        window.seen
        |> MapSet.put(nonce)
        |> Enum.filter(&(&1 > highest - @size))
        |> MapSet.new()

      %{highest: highest, seen: seen}
    end
  end

  window = ConnectionlessReplayWindow.new()
  {nonce, ciphertext} = get_msg_from(peer)

  {:ok, plaintext, window} =
    ConnectionlessReplayWindow.decrypt(recipient, nonce, ciphertext, aad, window)

  # A second delivery is rejected before Decibel decrypts it.
  {:error, :duplicate, ^window} =
    ConnectionlessReplayWindow.decrypt(recipient, nonce, ciphertext, aad, window)
  ```

  The window changes only after authentication succeeds. A failed ciphertext
  therefore does not prevent a later authentic packet with the same nonce from
  being tried.

  `rekey/2` changes the key but deliberately preserves the nonce. Peers must
  coordinate rekeying independently in each direction and must not reset their
  counters or replay windows when they rekey. Once a receive key is replaced,
  delayed packets encrypted under the old key can no longer be decrypted.

  """

  @typedoc "The role the party plays in the protocol."
  @type role :: :ini | :rsp

  @typedoc "A public-private Diffie-Hellman keypair."
  @type keypair :: {binary(), binary()}

  @typedoc "Key material and prologue data used to initialize a handshake."
  @type key_material :: %{
          optional(:s) => keypair(),
          optional(:rs) => binary(),
          optional(:e) => keypair(),
          optional(:re) => binary(),
          optional(:psks) => [<<_::256>>],
          optional(:prologue) => iodata()
        }

  @typedoc "An option used to initialize a handshake."
  @type option :: {:swap, role()} | {:registry, module()}

  @typedoc "An opaque, process-owned Noise session handle."
  @type session :: Decibel.Session.t()

  alias Decibel.{ChannelPair, Cipher, Handshake, Session}

  @max_message_size 65_535
  @max_transport_plaintext_size @max_message_size - 16

  @doc """
  Start a new handshake.

  The caller should provide a [protocol name](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers)
  and the role the caller will play in the protocol. The caller must provide all keys
  required by the protocol, including local static keys first used by later handshake
  messages. These are normally static keys or pre-shared keys (PSKs). Local ephemeral
  keys for ordinary handshakes are
  generated internally when their outbound `e` token is processed. The list of provided
  keys should be identified as follows:

  Before constructing a session, review
  [Authentication and key handling](#module-authentication-and-key-handling) and
  [Negotiation and rollback](#module-negotiation-and-rollback).

  - `:s`: the party's public-private static key pair as a tuple. It is required
    whenever the selected role uses a static key anywhere in the fully modified pattern.
  - `:rs`: the peer's public static key as a binary, only when the peer has a
    static pre-message.
  - `:e`: only for a fallback handshake where the caller sent the failed handshake's
  original ephemeral; the caller's public-private ephemeral key pair as a tuple.
  - `:re`: only for a fallback handshake where the peer sent the failed handshake's
  original ephemeral; the peer's ephemeral public key as a binary.
  - `:psks`: a list of [pre-shared symmetric keys](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys)
  (as binaries), exactly one 32-byte key for each `pskN` modifier.
  - `:prologue`: any [prologue](https://noiseprotocol.org/noise.html#prologue) data
    represented as iodata.

  Public and private DH values must each have the exact length required by the
  selected DH function: 32 bytes for `25519` or 56 bytes for `448`.

  The supported options are `:swap`, whose value must be `:ini` or `:rsp`, and
  `:registry`, whose value must be a module exporting `fetch!/1`. Each option may
  appear at most once.

  Ephemeral keypairs belong to exactly one protocol run. They must never be shared
  across sessions, processes, or protocol names. The fallback inputs above reuse a key
  within the same compound-protocol run; they do not make general reuse safe.

  Protocol names are limited to 255 bytes and must use the canonical Noise
  syntax. Modifiers are applied from left to right, so `pskN` after `fallback`
  indexes the remaining handshake messages. PSK modifiers whose relative order
  does not affect the resulting pattern must be sorted alphabetically, as
  required by [Noise section 8.1](https://noiseprotocol.org/noise.html#handshake-pattern-name-section).

  Raises `ArgumentError` for malformed or unsupported protocol names, invalid
  or non-canonical modifiers, impossible PSK placements, PSK lists that do not
  contain exactly one 32-byte key per modifier, missing or malformed static key
  material, invalid prologue iodata, and invalid options. It also raises
  `ArgumentError` for caller-supplied ephemeral keys outside their role-specific
  fallback pre-message or with lengths that do not match the selected DH
  function. Validation completes before any session state is stored.

  Returns an opaque session handle representing the handshake. The calling
  process owns the session for its lifetime; see
  [Ownership and lifetime](#module-ownership-and-lifetime).
  """
  @spec new(String.t(), role(), key_material(), [option()]) :: session()
  def new(protocol_name, role, keys \\ %{}, opts \\ []) do
    hs = Handshake.initialize(protocol_name, role, keys, opts, :safe)
    Session.create(hs)
  end

  @doc """
  Encrypt an outbound handshake message, optionally folding in application data.

  > The reader is encouraged to understand the ramifications of providing application
  > data _during_ the handshake. As the handshake is not yet completed, the properties
  > of any secure channel have not yet been established. Such data may even be sent in
  > the clear. Consult the [Payload Security Properties](https://noiseprotocol.org/noise.html#payload-security-properties)
  > in the specification for more information.

  Applications are responsible for
  [framing and authenticating termination](#module-framing-payloads-and-termination)
  and for their [failure policy](#module-failure-handling).

  Raises `ArgumentError` if the complete handshake message would exceed the Noise
  limit of 65,535 bytes. The maximum application-data size varies with the handshake
  pattern and cryptographic primitives because public keys and authentication tags
  are part of the same message.

  A peer public key received in an earlier message might not be used until this
  write step. If that key is invalid, this function raises
  `Decibel.DecryptionError` with `reason: :invalid_public_key`. The session state
  remains unchanged so the caller can abandon the handshake cleanly.

  Requires the session's `:handshake_write` phase. Ownership, closed/unknown
  handles, and a wrong handshake turn raise `Decibel.SessionError` before any
  state change.
  """
  @spec handshake_encrypt(session(), iodata()) :: iodata()
  def handshake_encrypt(session, plaintext \\ []) do
    hs = Session.fetch!(session, :handshake_encrypt, :handshake_write)
    validate_size!(plaintext, @max_message_size, "handshake plaintext")
    {hs, ciphertext} = Handshake.write_message(hs, plaintext)
    validate_size!(ciphertext, @max_message_size, "handshake message")
    Session.store!(session, hs)
    ciphertext
  end

  @doc """
  Decrypt an inbound handshake message, returning any optionally provided application
  data.

  Raises `Decibel.DecryptionError` with `reason: :truncated`,
  `:authentication_failed`, or `:invalid_public_key` if the peer message cannot be
  processed. Its `:remote_keys` field contains keys processed before the failure,
  and the stored handshake state remains unchanged. Raises `ArgumentError` if the
  message exceeds 65,535 bytes.

  See [Failure handling](#module-failure-handling) before deciding whether to
  abandon the handshake or enter a reviewed fallback protocol.

  Requires the session's `:handshake_read` phase. Ownership, closed/unknown
  handles, and a wrong handshake turn raise `Decibel.SessionError` before any
  state change.
  """
  @spec handshake_decrypt(session(), iodata()) :: iodata()
  def handshake_decrypt(session, ciphertext) do
    hs = Session.fetch!(session, :handshake_decrypt, :handshake_read)
    validate_size!(ciphertext, @max_message_size, "handshake message")
    {hs, plaintext} = Handshake.read_message(hs, ciphertext)
    Session.store!(session, hs)
    plaintext
  end

  @doc """
  Returns `true` if the handshake is complete, `false` otherwise.

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec is_handshake_complete?(session()) :: boolean()
  # Keep the established public API name for backwards compatibility.
  # credo:disable-for-next-line Credo.Check.Readability.PredicateFunctionNames
  def is_handshake_complete?(session) do
    case Session.fetch!(session, :is_handshake_complete, :any) do
      %Handshake{} -> false
      %ChannelPair{} -> true
    end
  end

  @doc """
  Returns a 32-byte handshake hash, unique to the established session.

  Returns `nil` if the handshake is not yet completed.

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec get_handshake_hash(session()) :: binary() | nil
  def get_handshake_hash(session) do
    case Session.fetch!(session, :get_handshake_hash, :any) do
      %Handshake{} -> nil
      %ChannelPair{} = cp -> ChannelPair.get_hash(cp)
    end
  end

  @doc """
  Encrypts a message over an established session, using an optionally
  provided AAD for message integrity.

  Returns the encrypted message.

  The application must provide
  [framing and authenticated termination](#module-framing-payloads-and-termination)
  and follow the
  [nonce and rekeying guidance](#module-nonces-replay-protection-and-rekeying).

  Raises `ArgumentError` if `plaintext` exceeds 65,519 bytes, the largest plaintext
  that leaves room for the 16-byte authentication tag within a Noise message.
  Raises `Decibel.TransportDirectionError` before any state change if outbound
  transport is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the outbound channel's
  nonce is exhausted.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec encrypt(session(), iodata(), iodata()) :: iodata()
  def encrypt(session, plaintext, ad \\ []) do
    channel_pair = Session.fetch!(session, :encrypt, :transport)
    validate_size!(plaintext, @max_transport_plaintext_size, "transport plaintext")
    {channel_pair, ciphertext} = ChannelPair.write_message(channel_pair, ad, plaintext)
    Session.store!(session, channel_pair)
    ciphertext
  end

  @doc """
  Decrypts a message over an established session, using an optionally
  provided AAD for message integrity.

  Returns the decrypted message. Raises `Decibel.DecryptionError` with
  `reason: :truncated` or `:authentication_failed` if the message cannot be
  decrypted. The inbound state and nonce remain unchanged on either failure.
  Raises `ArgumentError` if the message exceeds 65,535 bytes.
  Raises `Decibel.TransportDirectionError` before any state change if inbound
  transport is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the inbound channel's
  nonce is exhausted.

  See [Failure handling](#module-failure-handling) for the policy an application
  must apply to unauthenticated transport messages.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec decrypt(session(), iodata(), iodata()) :: iodata()
  def decrypt(session, ciphertext, ad \\ []) do
    channel_pair = Session.fetch!(session, :decrypt, :transport)
    validate_size!(ciphertext, @max_message_size, "transport message")
    {channel_pair, plaintext} = ChannelPair.read_message(channel_pair, ad, ciphertext)
    Session.store!(session, channel_pair)
    plaintext
  end

  @doc """
  Release the resources associated with the session.

  This discards handshake or transport state immediately, including pending key
  material. The state is also released automatically when the owner process
  terminates. The handle remains closed and cannot be reused.

  Invalid ownership or an unknown handle raises `Decibel.SessionError`. Calling
  `close/1` again raises it with `reason: :closed`.
  """
  @spec close(session()) :: :ok
  def close(session), do: Session.close!(session)

  @doc """
  Rekey the inbound or outbound channel of the session.

  Noise rekeying changes the selected channel's key but does not reset its
  nonce. Applications must coordinate rekeying with the peer and continue the
  existing counter. For connectionless transports, retain the corresponding
  replay window as well; delayed messages encrypted under the old key cannot be
  decrypted after rekeying.

  See
  [Nonces, replay protection, and rekeying](#module-nonces-replay-protection-and-rekeying)
  for the application responsibilities around this operation.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec rekey(session(), :in | :out) :: :ok
  def rekey(session, dir) do
    channel_pair = Session.fetch!(session, :rekey, :transport)
    validate_direction!(dir)
    Session.store!(session, ChannelPair.rekey(channel_pair, dir))
    :ok
  end

  @doc """
  Get the current nonce value of the specified cipher.

  Connectionless senders should read the outbound nonce immediately before
  calling `encrypt/3` and send that value with the ciphertext. See
  [Connectionless Transports](#module-connectionless-transports) for the replay
  protection the recipient must provide, and
  [Nonces, replay protection, and rekeying](#module-nonces-replay-protection-and-rekeying)
  for the safe-use requirements.

  After the final usable nonce, `2^64 - 2`, is consumed, this returns the
  reserved value `2^64 - 1` to indicate that the channel is exhausted.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError`.
  """
  @spec get_nonce(session(), :in | :out) :: Cipher.nonce()
  def get_nonce(session, dir) do
    channel_pair = Session.fetch!(session, :get_nonce, :transport)
    validate_direction!(dir)
    ChannelPair.get_n(channel_pair, dir)
  end

  @doc """
  Set the current value of nonce for the specified cipher.

  > #### Danger: low-level nonce control {: .warning}
  >
  > This function does not provide replay protection. Applications selecting
  > inbound nonces must reject every nonce that has already authenticated and
  > must record a nonce only after successful decryption. Applications should
  > normally read outbound nonces with `get_nonce/2`; moving an outbound nonce
  > backwards is rejected because reusing a nonce with the same key is a
  > catastrophic AEAD failure.

  The nonce must be an integer from `0` through `2^64 - 2`.

  An inbound nonce may be selected in any order. An outbound nonce may remain
  unchanged or move forward, but cannot move backwards. A rejected operation
  leaves session state unchanged.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the nonce is outside
  the usable range or would move the outbound channel backwards.

  See
  [Nonces, replay protection, and rekeying](#module-nonces-replay-protection-and-rekeying)
  before using this low-level operation.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec set_nonce(session(), :in | :out, Cipher.usable_nonce()) :: :ok
  def set_nonce(session, dir, n) do
    channel_pair = Session.fetch!(session, :set_nonce, :transport)
    validate_direction!(dir)
    Session.store!(session, ChannelPair.set_n(channel_pair, dir, n))
    :ok
  end

  @doc """
  Get the remote (static) key if available.

  A returned key is protocol output, not a trust decision. Authenticate it
  according to
  [Authentication and key handling](#module-authentication-and-key-handling).

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec get_remote_key(session()) :: nil | binary()
  def get_remote_key(session) do
    session
    |> Session.fetch!(:get_remote_key, :any)
    |> Map.get(:rs)
  end

  defp validate_direction!(direction) when direction in [:in, :out], do: :ok

  defp validate_direction!(direction) do
    raise ArgumentError, "direction must be :in or :out, got: #{inspect(direction)}"
  end

  defp validate_size!(data, maximum, description) do
    case IO.iodata_length(data) do
      size when size <= maximum ->
        :ok

      size ->
        raise ArgumentError,
              "#{description} must not exceed #{maximum} bytes, got #{size} bytes"
    end
  end
end
