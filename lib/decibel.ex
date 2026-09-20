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

  ### Creation

  Each party begins by creating a new handshake, via `new/4`, specifying the
  [protocol name](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers),
  the role the party plays in the handshake (`:ini` for initiator, `:rsp` for
  responder), and optionally any pre-message keys.

  ```
  # In the IK handshake, the responder's public (static) key is known to the
  # initiator prior to the handshake.
  keys = %{rs: <<...>>}
  ini  = Decibel.new("Noise_IK_448_ChaChaPoly_BLAKE2b", :ini, keys)
  ```

  The result of `new/4` is a reference used for the rest of the session.

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

  Once the session is complete, each party should call `close/1` to free the
  resources associated with the it.

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
      rsp = Decibel.new("Noise_XXfallback_25519_ChaChaPoly_Blake2b", :rsp, %{re: re}, swap: :rsp)
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

  This example shows how to send data over such a transport:

  ```elixir
  # First, grab the nonce for the outbound channel
  n = Decibel.get_nonce(ref, :out)
  # Encrypt the data
  ciphertext = Decibel.encrypt(ref, plaintext, aad)
  # Send both the nonce and the ciphertext
  send(peer, {n, ciphertext})
  ```

  The receiving side is as follows:

  ```elixir
  # Receive the message
  {n, ciphertext} = get_msg_from(peer)
  # Set the nonce for the inbound channel using the received n
  :ok = Decibel.set_nonce(ref, :in, n)
  # Decrypt the ciphertext
  plaintext = Decibel.decrypt(ref, ciphertext, aad)
  ```

  """

  @typedoc "The role the party plays in the protocol."
  @type role :: :ini | :rsp

  alias Decibel.{ChannelPair, Cipher, Handshake}

  @max_message_size 65_535
  @max_transport_plaintext_size @max_message_size - 16

  @doc """
  Start a new handshake.

  The caller should provide a [protocol name](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers)
  and the role the caller will play in the protocol. The caller should provide any keys
  required by the protocol prior to advancing the handshake. These are normally static
  keys or pre-shared keys (PSKs). Local ephemeral keys for ordinary handshakes are
  generated internally when their outbound `e` token is processed. The list of provided
  keys should be identified as follows:

  - `:s`: the party's public-private static key pair as a tuple.
  - `:rs`: the peer's public static key as a binary.
  - `:e`: only for a fallback handshake where the caller sent the failed handshake's
  original ephemeral; the caller's public-private ephemeral key pair as a tuple.
  - `:re`: only for a fallback handshake where the peer sent the failed handshake's
  original ephemeral; the peer's ephemeral public key as a binary.
  - `:psks`: a list of [pre-shared symmetric keys](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys)
  (as binaries), exactly one 32-byte key for each `pskN` modifier.
  - `:prologue`: any [prologue](https://noiseprotocol.org/noise.html#prologue) data

  Ephemeral keypairs belong to exactly one protocol run. They must never be shared
  across sessions, processes, or protocol names. The fallback inputs above reuse a key
  within the same compound-protocol run; they do not make general reuse safe.

  Protocol names are limited to 255 bytes and must use the canonical Noise
  syntax. Modifiers are applied from left to right, so `pskN` after `fallback`
  indexes the remaining handshake messages. PSK modifiers whose relative order
  does not affect the resulting pattern must be sorted alphabetically, as
  required by [Noise section 8.1](https://noiseprotocol.org/noise.html#handshake-pattern-name-section).

  Raises `ArgumentError` for malformed or unsupported protocol names, invalid
  or non-canonical modifiers, impossible PSK placements, and PSK lists that do
  not contain exactly one 32-byte key per modifier. It also raises `ArgumentError`
  for caller-supplied ephemeral keys outside their role-specific fallback
  pre-message or with lengths that do not match the selected DH function. Other
  missing key material also raises an exception.

  Returns a reference representing the handshake.
  """
  @spec new(String.t(), role(), map, keyword) :: reference()
  def new(protocol_name, role, keys \\ %{}, opts \\ []) do
    hs = Handshake.initialize(protocol_name, role, keys, opts, :safe)
    ref = make_ref()
    Process.put(ref, hs)
    ref
  end

  @doc """
  Encrypt an outbound handshake message, optionally folding in application data.

  > The reader is encouraged to understand the ramifications of providing application
  > data _during_ the handshake. As the handshake is not yet completed, the properties
  > of any secure channel have not yet been established. Such data may even be sent in
  > the clear. Consult the [Payload Security Properties](https://noiseprotocol.org/noise.html#payload-security-properties)
  > in the specification for more information.

  Raises `ArgumentError` if the complete handshake message would exceed the Noise
  limit of 65,535 bytes. The maximum application-data size varies with the handshake
  pattern and cryptographic primitives because public keys and authentication tags
  are part of the same message.

  A peer public key received in an earlier message might not be used until this
  write step. If that key is invalid, this function raises
  `Decibel.DecryptionError` with `reason: :invalid_public_key`. The session state
  remains unchanged so the caller can abandon the handshake cleanly.
  """
  @spec handshake_encrypt(reference(), iodata()) :: iodata()
  def handshake_encrypt(ref, plaintext \\ []) when is_reference(ref) do
    validate_size!(plaintext, @max_message_size, "handshake plaintext")
    {hs, ciphertext} = Handshake.write_message(Process.get(ref), plaintext)
    validate_size!(ciphertext, @max_message_size, "handshake message")
    Process.put(ref, hs)
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
  """
  @spec handshake_decrypt(reference(), iodata()) :: iodata()
  def handshake_decrypt(ref, ciphertext) when is_reference(ref) do
    validate_size!(ciphertext, @max_message_size, "handshake message")
    {hs, plaintext} = Handshake.read_message(Process.get(ref), ciphertext)
    Process.put(ref, hs)
    plaintext
  end

  @doc """
  Returns `true` if the handshake is complete, `false` otherwise.
  """
  @spec is_handshake_complete?(reference()) :: boolean()
  # Keep the established public API name for backwards compatibility.
  # credo:disable-for-next-line Credo.Check.Readability.PredicateFunctionNames
  def is_handshake_complete?(ref) do
    !!get_handshake_hash(ref)
  end

  @doc """
  Returns a 32-byte handshake hash, unique to the established session.

  Returns `nil` if the handshake is not yet completed.
  """
  @spec get_handshake_hash(reference()) :: binary() | nil
  def get_handshake_hash(ref) when is_reference(ref) do
    case Process.get(ref) do
      %Handshake{} -> nil
      %ChannelPair{} = cp -> ChannelPair.get_hash(cp)
    end
  end

  @doc """
  Encrypts a message over an established session, using an optionally
  provided AAD for message integrity.

  Returns the encrypted message.

  Raises `ArgumentError` if `plaintext` exceeds 65,519 bytes, the largest plaintext
  that leaves room for the 16-byte authentication tag within a Noise message.
  Raises `Decibel.TransportDirectionError` before any state change if outbound
  transport is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the outbound channel's
  nonce is exhausted.
  """
  @spec encrypt(reference(), iodata(), iodata()) :: iodata()
  def encrypt(ref, plaintext, ad \\ []) do
    validate_size!(plaintext, @max_transport_plaintext_size, "transport plaintext")
    {cs, ciphertext} = ChannelPair.write_message(Process.get(ref), ad, plaintext)
    Process.put(ref, cs)
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
  """
  @spec decrypt(reference(), iodata(), iodata()) :: iodata()
  def decrypt(ref, ciphertext, ad \\ []) do
    validate_size!(ciphertext, @max_message_size, "transport message")
    {cs, plaintext} = ChannelPair.read_message(Process.get(ref), ad, ciphertext)
    Process.put(ref, cs)
    plaintext
  end

  @doc """
  Release the resources associated with the session.

  These resources are automatically released when the process terminates, but
  this call may be used to eagerly clean them up.
  """
  @spec close(reference()) :: :ok
  def close(ref) do
    Process.delete(ref)
    :ok
  end

  @doc """
  Rekey the inbound or outbound channel of the session.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.
  """
  @spec rekey(reference, :in | :out) :: :ok
  def rekey(ref, dir) when is_reference(ref) and dir in [:in, :out] do
    Process.put(ref, ChannelPair.rekey(Process.get(ref), dir))
    :ok
  end

  @doc """
  Get the current nonce value of the specified cipher.

  After the final usable nonce, `2^64 - 2`, is consumed, this returns the
  reserved value `2^64 - 1` to indicate that the channel is exhausted.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.
  """
  @spec get_nonce(reference(), :in | :out) :: Cipher.nonce()
  def get_nonce(ref, dir) when is_reference(ref) and dir in [:in, :out] do
    ChannelPair.get_n(Process.get(ref), dir)
  end

  @doc """
  Set the current value of nonce for the specified cipher.

  The nonce must be an integer from `0` through `2^64 - 2`.

  Raises `Decibel.TransportDirectionError` before any state change if the
  selected direction is not permitted by a one-way handshake.
  Raises `Decibel.NonceError` without changing state if the nonce is outside
  the usable range.
  """
  @spec set_nonce(reference(), :in | :out, Cipher.usable_nonce()) :: :ok
  def set_nonce(ref, dir, n) when is_reference(ref) and dir in [:in, :out] do
    Process.put(ref, ChannelPair.set_n(Process.get(ref), dir, n))
    :ok
  end

  @doc """
  Get the remote (static) key if available.
  """
  @spec get_remote_key(reference) :: nil | binary()
  def get_remote_key(ref) when is_reference(ref) do
    Map.get(Process.get(ref), :rs)
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
