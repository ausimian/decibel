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

  ## API conventions

  Decibel has a direct, raising API. Operations that produce data return it
  directly: a session handle, ciphertext or plaintext, a boolean, a handshake
  hash, a nonce, or a remote key. `encrypt_with_nonce/3` returns the nonce it
  used together with the ciphertext. Operations whose only result is a state
  change return `:ok`: `close/1`, `rekey/2`, and `set_nonce/3`.

  Plaintext, associated data, and inbound Noise messages accept iodata. The
  message and payload return types are also iodata, so callers that need a
  binary for framing or transport I/O should use `IO.iodata_to_binary/1` rather
  than depend on an incidental list or binary shape.

  There are no bang and non-bang variants. Invalid construction and arguments
  raise `ArgumentError`; peer-message failures raise
  `Decibel.DecryptionError`; nonce and one-way direction failures raise
  `Decibel.NonceError` and `Decibel.TransportDirectionError`; ownership,
  lifetime, or phase failures raise `Decibel.SessionError`; and handoff ticket
  failures raise `Decibel.HandoffError`. Applications should
  rescue these stable exceptions only at boundaries where they have an explicit
  recovery or failure policy. Rejected operations do not commit session state.

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

  Consider the unauthenticated NN handshake defined in the Noise Protocol:

  ```text
  NN:
    -> e
    <- e, ee
  ```

  The parties agree on this handshake and its cryptographic parameters and
  express this in a protocol name. This runnable example drives both roles in
  one process; a real peer process must create and operate its own session and
  exchange framed Noise messages rather than handles.

      iex> initiator = Decibel.new("Noise_NN_25519_AESGCM_SHA256", :ini)
      iex> responder = Decibel.new("Noise_NN_25519_AESGCM_SHA256", :rsp)
      iex> Decibel.handshake_encrypt(initiator) |> then(&Decibel.handshake_decrypt(responder, &1))
      ""
      iex> Decibel.handshake_encrypt(responder) |> then(&Decibel.handshake_decrypt(initiator, &1))
      ""
      iex> ciphertext = Decibel.encrypt(initiator, "Hello, world")
      iex> Decibel.decrypt(responder, ciphertext)
      "Hello, world"
      iex> {Decibel.close(initiator), Decibel.close(responder)}
      {:ok, :ok}

  The [Getting Started](getting-started.md) guide adds authenticated key
  validation, application framing, the exact message-size boundary, and focused
  usage recipes.

  ## Lifecycle

  ### Ownership and lifetime

  `new/4` returns an opaque `t:session/0` handle. The session state belongs to
  the process that calls `new/4` and is stored in that process until `close/1`
  is called or the owner process exits. Closing or handing off a session
  removes everything Decibel stored for it, so a long-lived owner does not
  accumulate storage for sessions it no longer holds. A handle contains no
  cryptographic state and must not be inspected, altered, or constructed by
  callers.

  Every operation on a session must run serially in its owner process. Do not
  pass the handle to a task, worker, or peer process, and do not call it
  concurrently. A `GenServer` or similar long-lived process can own a session
  and serialize all operations in its callbacks. If that process terminates,
  its supervisor must establish a new session. The sole exception is an
  explicit, one-time handoff while the handshake is still in progress.

  `handoff/2` returns a ticket to the current owner, which must deliver it to
  the designated local target process through its own messaging protocol. The
  target calls `accept_handoff/1` in that process and receives a new handle.
  The old handle is closed as soon as `handoff/2` succeeds. A ticket can be
  accepted once, and the accepted session cannot be handed off again. An
  unclaimed ticket expires after 60 seconds and is discarded if the target
  exits. An abandoned or failed transfer cannot restore the old handle. A
  target that exits after accepting also discards the session state it owns.
  Handoff is unavailable once transport begins; applications must transfer
  their own peer configuration, socket, and replay bookkeeping separately.

  Using a structurally valid handle in another process raises `Decibel.SessionError` with
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
  each party can call `handshake_complete?/1` after each handshake
  encryption/decryption.

  Once the handshake is complete, a secure channel is established with the
  [properties](https://noiseprotocol.org/noise.html#payload-security-properties) of
  the selected protocol.

  Additionally, once the handshake is complete, a unique 'session-hash' is available
  via `handshake_hash/1` - see the [channel-binding](https://noiseprotocol.org/noise.html#channel-binding)
  section of the specification for more details.

  ### Session

  Once the handshake is complete, the parties use `encrypt/3` and `decrypt/3` to
  exchange 'application' messages between each other. Both functions provide for optional
  'associated authenticated data' to be specified, that provides message-integrity
  assurance for the application data.

  Protocols that carry an explicit nonce with each message use
  `encrypt_with_nonce/3` to seal under the next outbound nonce and learn its
  value, and the `:nonce` option of `decrypt/4` to open at a received nonce.
  Each is a single session operation. See
  [Connectionless Transports](connectionless-transports.md).

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

  """

  @typedoc "The role the party plays in the protocol."
  @type role :: :ini | :rsp

  @typedoc "A public-private Diffie-Hellman keypair."
  @type keypair :: {binary(), binary()}

  @typedoc """
  A Noise handshake hash.

  `SHA256` and `BLAKE2s` produce 32-byte hashes; `SHA512` and `BLAKE2b`
  produce 64-byte hashes.
  """
  @type handshake_hash :: <<_::256>> | <<_::512>>

  @typedoc "A cipher nonce, including Noise's reserved exhausted value."
  @type nonce :: 0..18_446_744_073_709_551_615

  @typedoc "A nonce value that may be selected for an active cipher."
  @type usable_nonce :: 0..18_446_744_073_709_551_614

  @typedoc "Key material and prologue data used to initialize a handshake."
  @type key_material :: %{
          optional(:s) => keypair(),
          optional(:rs) => binary(),
          optional(:e) => keypair(),
          optional(:re) => binary(),
          optional(:psks) => [<<_::256>>],
          optional(:prologue) => iodata()
        }

  @typedoc "The role whose outbound channel uses the first split key."
  @type option :: {:swap, role()}

  @typedoc "The inbound nonce at which `decrypt/4` opens a transport message."
  @type decrypt_option :: {:nonce, usable_nonce()}

  @typedoc "An opaque, process-owned Noise session handle."
  @type session :: Decibel.Session.t()

  @typedoc "An opaque, single-use ticket for transferring an in-progress handshake."
  @type handoff_ticket :: Decibel.Handoff.t()

  alias Decibel.{ChannelPair, Handoff, Handshake, Session}

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
  [Authentication and key handling](security.md#authentication-and-key-handling) and
  [Negotiation and rollback](security.md#negotiation-and-rollback).

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

  The only supported option is `:swap`, whose value must be `:ini` or `:rsp` and
  defaults to `:ini`. For interactive handshakes, the named role uses the first
  key returned by Noise `Split()` as its outbound key, and the other role uses
  that key as its inbound key. Both peers must use the same value. Noise Pipes
  fallback uses `swap: :rsp` because the responder sends the first fallback
  message. This option never reverses the fixed direction of a one-way
  handshake.

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
  [Ownership and lifetime](`m:Decibel#module-ownership-and-lifetime`).
  """
  @spec new(String.t(), role(), key_material(), [option()]) :: session()
  def new(protocol_name, role, keys \\ %{}, opts \\ []) do
    validate_new_arguments!(protocol_name, role, keys)
    hs = Handshake.initialize(protocol_name, role, keys, opts, :safe)
    Session.create(hs)
  end

  @doc """
  Transfer an in-progress handshake to a live local process.

  Returns an opaque ticket. The current owner must deliver it to `target` through
  its own messaging protocol; this function sends no application message. The
  old handle is closed immediately on success and cannot be used or handed off
  again. Only `target` can call `accept_handoff/1` with the ticket. If the
  target exits or does not accept within 60 seconds, the cryptographic state is
  discarded. A failed call leaves the current session intact.

  Invalid ownership, closed or unknown handles, and transport-phase handoff
  raise `Decibel.SessionError`. A second handoff raises it with
  `reason: :already_handed_off`. An invalid, dead, or remote target raises
  `Decibel.HandoffError` with `reason: :invalid_target`.

      ticket = Decibel.handoff(session, peer_pid)
      GenServer.call(peer_pid, {:accept_noise_handshake, ticket, metadata})

  The target process should call `accept_handoff/1` in its callback.
  """
  @spec handoff(session(), pid()) :: handoff_ticket()
  def handoff(session, target), do: Session.handoff!(session, target)

  @doc """
  Accept a one-time handshake handoff in its designated target process.

  Returns a new session handle owned by the caller, containing the same live
  Noise handshake state and pending turn. The ticket cannot be claimed again.
  An invalid ticket raises `Decibel.HandoffError` with `reason: :invalid_ticket`;
  a valid ticket used by another process uses `:not_target`; and an already
  claimed, expired, or abandoned ticket uses `:unavailable`. A stalled ticket
  process uses `:timeout` without claiming that its state was discarded.

      # In peer_pid's GenServer.handle_call/3:
      session = Decibel.accept_handoff(ticket)
  """
  @spec accept_handoff(handoff_ticket()) :: session()
  def accept_handoff(ticket), do: ticket |> Handoff.accept!() |> Session.create_accepted()

  @doc """
  Encrypt an outbound handshake message, optionally folding in application data.

  > The reader is encouraged to understand the ramifications of providing application
  > data _during_ the handshake. As the handshake is not yet completed, the properties
  > of any secure channel have not yet been established. Such data may even be sent in
  > the clear. Consult the [Payload Security Properties](https://noiseprotocol.org/noise.html#payload-security-properties)
  > in the specification for more information.

  Applications are responsible for
  [framing and authenticating termination](security.md#framing-payloads-and-termination)
  and for their [failure policy](security.md#failure-handling).

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
    {slot, hs} = Session.fetch!(session, :handshake_encrypt, :handshake_write)
    validate_size!(plaintext, @max_message_size, "handshake plaintext")
    {hs, ciphertext} = Handshake.write_message(hs, plaintext)
    validate_size!(ciphertext, @max_message_size, "handshake message")
    Session.store!(slot, hs)
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

  See [Failure handling](security.md#failure-handling) before deciding whether to
  abandon the handshake or enter a reviewed fallback protocol.

  Requires the session's `:handshake_read` phase. Ownership, closed/unknown
  handles, and a wrong handshake turn raise `Decibel.SessionError` before any
  state change.
  """
  @spec handshake_decrypt(session(), iodata()) :: iodata()
  def handshake_decrypt(session, ciphertext) do
    {slot, hs} = Session.fetch!(session, :handshake_decrypt, :handshake_read)
    validate_size!(ciphertext, @max_message_size, "handshake message")
    {hs, plaintext} = Handshake.read_message(hs, ciphertext)
    Session.store!(slot, hs)
    plaintext
  end

  @doc """
  Returns `true` if the handshake is complete, `false` otherwise.

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec handshake_complete?(session()) :: boolean()
  def handshake_complete?(session) do
    case Session.fetch!(session, :handshake_complete?, :any) do
      {_slot, %Handshake{}} -> false
      {_slot, %ChannelPair{}} -> true
    end
  end

  @doc """
  Deprecated alias for `handshake_complete?/1`.

  Scheduled for removal in Decibel 2.0.
  """
  @deprecated "Use handshake_complete?/1 instead"
  @spec is_handshake_complete?(session()) :: boolean()
  # credo:disable-for-next-line Credo.Check.Readability.PredicateFunctionNames
  def is_handshake_complete?(session), do: handshake_complete?(session)

  @doc """
  Returns the handshake hash unique to the established session.

  The hash is 32 bytes for `SHA256` and `BLAKE2s`, or 64 bytes for `SHA512`
  and `BLAKE2b`. Returns `nil` if the handshake is not yet completed.

  ## Examples

      iex> initiator = Decibel.new("Noise_NN_25519_ChaChaPoly_SHA256", :ini)
      iex> responder = Decibel.new("Noise_NN_25519_ChaChaPoly_SHA256", :rsp)
      iex> Decibel.handshake_encrypt(initiator) |> then(&Decibel.handshake_decrypt(responder, &1))
      ""
      iex> Decibel.handshake_encrypt(responder) |> then(&Decibel.handshake_decrypt(initiator, &1))
      ""
      iex> match?(<<_::32-bytes>>, Decibel.handshake_hash(initiator))
      true
      iex> Decibel.handshake_hash(initiator) == Decibel.handshake_hash(responder)
      true
      iex> {Decibel.close(initiator), Decibel.close(responder)}
      {:ok, :ok}

      iex> initiator = Decibel.new("Noise_NN_448_AESGCM_BLAKE2b", :ini)
      iex> responder = Decibel.new("Noise_NN_448_AESGCM_BLAKE2b", :rsp)
      iex> Decibel.handshake_encrypt(initiator) |> then(&Decibel.handshake_decrypt(responder, &1))
      ""
      iex> Decibel.handshake_encrypt(responder) |> then(&Decibel.handshake_decrypt(initiator, &1))
      ""
      iex> match?(<<_::64-bytes>>, Decibel.handshake_hash(initiator))
      true
      iex> Decibel.handshake_hash(initiator) == Decibel.handshake_hash(responder)
      true
      iex> {Decibel.close(initiator), Decibel.close(responder)}
      {:ok, :ok}

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec handshake_hash(session()) :: handshake_hash() | nil
  def handshake_hash(session) do
    case Session.fetch!(session, :handshake_hash, :any) do
      {_slot, %Handshake{}} -> nil
      {_slot, %ChannelPair{} = cp} -> ChannelPair.get_hash(cp)
    end
  end

  @doc """
  Deprecated alias for `handshake_hash/1`.

  Scheduled for removal in Decibel 2.0.
  """
  @deprecated "Use handshake_hash/1 instead"
  @spec get_handshake_hash(session()) :: handshake_hash() | nil
  def get_handshake_hash(session), do: handshake_hash(session)

  @doc """
  Encrypts a message over an established session, using an optionally
  provided AAD for message integrity.

  Returns the encrypted message.

  The application must provide
  [framing and authenticated termination](security.md#framing-payloads-and-termination)
  and follow the
  [nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying).

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
    {slot, channel_pair} = Session.fetch!(session, :encrypt, :transport)
    validate_size!(plaintext, @max_transport_plaintext_size, "transport plaintext")
    {channel_pair, ciphertext} = ChannelPair.write_message(channel_pair, ad, plaintext)
    Session.store!(slot, channel_pair)
    ciphertext
  end

  @doc """
  Encrypts a message under the next outbound nonce and returns that nonce with
  the ciphertext.

  Returns `{nonce, ciphertext}`, where `nonce` is the value this call consumed.
  It is equivalent to reading `nonce(session, :out)` and then calling
  `encrypt/3`, but it is a single session operation. Protocols that send the
  nonce alongside each message, such as
  [connectionless transports](connectionless-transports.md), should use it.

  The application must provide
  [framing and authenticated termination](security.md#framing-payloads-and-termination)
  and follow the
  [nonce and rekeying guidance](security.md#nonces-replay-protection-and-rekeying).

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
  @spec encrypt_with_nonce(session(), iodata(), iodata()) :: {usable_nonce(), iodata()}
  def encrypt_with_nonce(session, plaintext, ad \\ []) do
    {slot, channel_pair} = Session.fetch!(session, :encrypt_with_nonce, :transport)
    validate_size!(plaintext, @max_transport_plaintext_size, "transport plaintext")

    {channel_pair, nonce, ciphertext} =
      ChannelPair.write_message_with_nonce(channel_pair, ad, plaintext)

    Session.store!(slot, channel_pair)
    {nonce, ciphertext}
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

  See [Failure handling](security.md#failure-handling) for the policy an application
  must apply to unauthenticated transport messages.

  ## Options

    * `:nonce` - decrypt at this inbound nonce, an integer from `0` through
      `2^64 - 2`, instead of the channel's current one. After a successful
      decryption the inbound nonce is the given value plus one, as with
      `set_nonce/3` followed by `decrypt/3`, but in a single session
      operation. On any failure the inbound nonce keeps its previous value.
      Raises `Decibel.NonceError` with `reason: :out_of_range`, without
      changing state, for a value outside the usable range.

  > #### Danger: no replay protection {: .warning}
  >
  > Like `set_nonce/3`, the `:nonce` option does not provide replay
  > protection. The application must reject every nonce that has already
  > authenticated and record a nonce only after successful decryption. See
  > [Connectionless Transports](connectionless-transports.md).

  Raises `ArgumentError` if `opts` is not a keyword list, contains an
  unsupported option, or repeats `:nonce`.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec decrypt(session(), iodata(), iodata(), [decrypt_option()]) :: iodata()
  def decrypt(session, ciphertext, ad \\ [], opts \\ []) do
    {slot, channel_pair} = Session.fetch!(session, :decrypt, :transport)
    validate_size!(ciphertext, @max_message_size, "transport message")

    {channel_pair, plaintext} =
      case validate_decrypt_options!(opts) do
        {:ok, nonce} -> ChannelPair.read_message_at(channel_pair, nonce, ad, ciphertext)
        :error -> ChannelPair.read_message(channel_pair, ad, ciphertext)
      end

    Session.store!(slot, channel_pair)
    plaintext
  end

  @doc """
  Release the resources associated with the session.

  Returns `:ok` after discarding the session state.

  This discards handshake or transport state immediately, including pending key
  material, and removes the session's storage from the owner process. The state
  is also released automatically when the owner process terminates. The handle
  remains closed and cannot be reused.

  Invalid ownership or an unknown handle raises `Decibel.SessionError`. Calling
  `close/1` again raises it with `reason: :closed`.
  """
  @spec close(session()) :: :ok
  def close(session), do: Session.close!(session)

  @doc """
  Rekey the inbound or outbound channel of the session.

  Returns `:ok` after replacing the selected key.

  Noise rekeying changes the selected channel's key but does not reset its
  nonce. Applications must coordinate rekeying with the peer and continue the
  existing counter. For connectionless transports, retain the corresponding
  replay window as well; delayed messages encrypted under the old key cannot be
  decrypted after rekeying.

  See
  [Nonces, replay protection, and rekeying](security.md#nonces-replay-protection-and-rekeying)
  for the application responsibilities around this operation.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec rekey(session(), :in | :out) :: :ok
  def rekey(session, dir) do
    {slot, channel_pair} = Session.fetch!(session, :rekey, :transport)
    validate_direction!(dir)
    Session.store!(slot, ChannelPair.rekey(channel_pair, dir))
    :ok
  end

  @doc """
  Get the current nonce value of the specified cipher.

  Connectionless senders should use `encrypt_with_nonce/3`, which returns the
  outbound nonce it consumed, and send that value with the ciphertext. See
  [Connectionless Transports](connectionless-transports.md) for the replay
  protection the recipient must provide, and
  [Nonces, replay protection, and rekeying](security.md#nonces-replay-protection-and-rekeying)
  for the safe-use requirements.

  After the final usable nonce, `2^64 - 2`, is consumed, this returns the
  reserved value `2^64 - 1` to indicate that the channel is exhausted.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError`.
  """
  @spec nonce(session(), :in | :out) :: nonce()
  def nonce(session, dir) do
    {_slot, channel_pair} = Session.fetch!(session, :nonce, :transport)
    validate_direction!(dir)
    ChannelPair.get_n(channel_pair, dir)
  end

  @doc """
  Deprecated alias for `nonce/2`.

  Scheduled for removal in Decibel 2.0.
  """
  @deprecated "Use nonce/2 instead"
  @spec get_nonce(session(), :in | :out) :: nonce()
  def get_nonce(session, dir), do: nonce(session, dir)

  @doc """
  Set the current value of nonce for the specified cipher.

  Returns `:ok` after selecting the nonce.

  > #### Danger: low-level nonce control {: .warning}
  >
  > This function does not provide replay protection. Applications selecting
  > inbound nonces must reject every nonce that has already authenticated and
  > must record a nonce only after successful decryption. Applications should
  > normally read outbound nonces with `nonce/2`; moving an outbound nonce
  > backwards is rejected because reusing a nonce with the same key is a
  > catastrophic AEAD failure.

  To decrypt a message at a received inbound nonce, prefer the `:nonce`
  option of `decrypt/4`, which selects the nonce and decrypts in one
  operation.

  The nonce must be an integer from `0` through `2^64 - 2`.

  An inbound nonce may be selected in any order. An outbound nonce may remain
  unchanged or move forward, but cannot move backwards. A rejected operation
  leaves session state unchanged.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the nonce is outside
  the usable range or would move the outbound channel backwards.

  See
  [Nonces, replay protection, and rekeying](security.md#nonces-replay-protection-and-rekeying)
  before using this low-level operation.

  Requires the `:transport` phase. Invalid ownership, a closed/unknown handle,
  or use during the handshake raises `Decibel.SessionError` before any state
  change.
  """
  @spec set_nonce(session(), :in | :out, usable_nonce()) :: :ok
  def set_nonce(session, dir, n) do
    {slot, channel_pair} = Session.fetch!(session, :set_nonce, :transport)
    validate_direction!(dir)
    Session.store!(slot, ChannelPair.set_n(channel_pair, dir, n))
    :ok
  end

  @doc """
  Get the remote (static) key if available.

  A returned key is protocol output, not a trust decision. Authenticate it
  according to
  [Authentication and key handling](security.md#authentication-and-key-handling).

  This accessor is valid during either handshake turn and transport. Invalid
  ownership or a closed/unknown handle raises `Decibel.SessionError`.
  """
  @spec remote_key(session()) :: nil | binary()
  def remote_key(session) do
    {_slot, state} = Session.fetch!(session, :remote_key, :any)
    Map.get(state, :rs)
  end

  @doc """
  Deprecated alias for `remote_key/1`.

  Scheduled for removal in Decibel 2.0.
  """
  @deprecated "Use remote_key/1 instead"
  @spec get_remote_key(session()) :: binary() | nil
  def get_remote_key(session), do: remote_key(session)

  defp validate_new_arguments!(protocol_name, role, keys) do
    is_binary(protocol_name) || raise ArgumentError, "protocol name must be a string"
    role in [:ini, :rsp] || raise ArgumentError, "role must be :ini or :rsp"
    is_map(keys) || raise ArgumentError, "key material must be a map"
  end

  defp validate_direction!(direction) when direction in [:in, :out], do: :ok

  defp validate_direction!(direction) do
    raise ArgumentError, "direction must be :in or :out, got: #{inspect(direction)}"
  end

  defp validate_decrypt_options!(opts) do
    Keyword.keyword?(opts) || raise ArgumentError, "options must be a keyword list"

    case Enum.find(Keyword.keys(opts), &(&1 != :nonce)) do
      nil -> :ok
      key -> raise ArgumentError, "unsupported decrypt option: #{inspect(key)}"
    end

    if length(Keyword.get_values(opts, :nonce)) > 1 do
      raise ArgumentError, "decrypt option :nonce may only be specified once"
    end

    Keyword.fetch(opts, :nonce)
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
