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
  which point a secure, symmetric channel is established that either party may
  use to encrypt and decrypt outbound and inbound messages respectively.

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

  If an AEAD decryption failure occurs, a `Decibel.DecryptionError` is raised.
  Additionally if this error occurs during a handshake, the error's `:remote_keys`
  property will contain any remote public keys processed during the handshake, up
  to the point of failure.

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

  - The retrievel of the remote ephemeral (`re`) key from the error
  - The prepopulation of that key in the responder's new handshake (other keys omitted
    for brevity)
  - The use of the `[swap: :rsp]` option - this is required to ensure the split cipher
    channels are correctly paired after the handshake.

  ## Connectionless Transports

  Once the handshake completes, Noise provides support for the encryption and decryption
  of messages over connectionless i.e. potentially _unordered_, potentially _lossy_
  transports, and Decibel honours this support.

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

  alias Decibel.{Handshake, ChannelPair, Crypto}

  @doc """
  Start a new handshake.

  The caller should provide a [protocol name](https://noiseprotocol.org/noise.html#protocol-names-and-modifiers)
  and the role the caller will play in the protocol. The caller should provide any keys
  required by the protocol prior to advancing the handshake. This are typically either
  static keys or pre-shared keys (PSKs), but ephemeral keys may also be provided. The
  list of provided keys should be identified as follows:

  - `:s`: the party's public-private static key pair as a tuple.
  - `:rs`: the peer's public static key as a binary.
  - `:psks`: a list of [pre-shared symmetric keys](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys)
  (as binaries), one for each psk modifier.
  - `:prologue`: any [prologue](https://noiseprotocol.org/noise.html#prologue) data

  This function will raise an exception if any required keys are missing.

  Returns a reference representing the handshake.
  """
  @spec new(String.t(), role(), map, keyword) :: reference()
  def new(protocol_name, role, keys \\ %{}, opts \\ []) do
    hs = Handshake.initialize(protocol_name, role, keys, opts)
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
  """
  @spec handshake_encrypt(reference(), iodata()) :: iodata()
  def handshake_encrypt(ref, plaintext \\ []) when is_reference(ref) do
    {hs, ciphertext} = Handshake.write_message(Process.get(ref), plaintext)
    Process.put(ref, hs)
    ciphertext
  end

  @doc """
  Decrypt an inbound handshake message, returning any optionally provided application
  data.

  The function will raise a `Decibel.DecryptionError` if the handshake data does not
  decrypt correctly.
  """
  @spec handshake_decrypt(reference(), iodata()) :: iodata()
  def handshake_decrypt(ref, ciphertext) when is_reference(ref) do
    {hs, plaintext} = Handshake.read_message(Process.get(ref), ciphertext)
    Process.put(ref, hs)
    plaintext
  end

  @doc """
  Returns `true` if the handshake is complete, `false` otherwise.
  """
  @spec is_handshake_complete?(reference()) :: boolean()
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
  """
  @spec encrypt(reference(), iodata(), iodata()) :: iodata()
  def encrypt(ref, plaintext, ad \\ []) do
    {cs, ciphertext} = ChannelPair.write_message(Process.get(ref), ad, plaintext)
    Process.put(ref, cs)
    ciphertext
  end

  @doc """
  Decrypts a message over an established session, using an optionally
  provided AAD for message integrity.

  Returns the decrypted message, or raises a `RuntimeException` if the
  message cannot be decrypted.
  """
  @spec decrypt(reference(), iodata(), iodata()) :: iodata()
  def decrypt(ref, ciphertext, ad \\ []) do
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
  """
  @spec rekey(reference, :in | :out) :: :ok
  def rekey(ref, dir) when is_reference(ref) and dir in [:in, :out] do
    Process.put(ref, ChannelPair.rekey(Process.get(ref), dir))
    :ok
  end

  @doc """
  Get the current nonce value of the specified cipher.
  """
  @spec get_nonce(reference(), :in | :out) :: non_neg_integer
  def get_nonce(ref, dir) when is_reference(ref) and dir in [:in, :out] do
    ChannelPair.get_n(Process.get(ref), dir)
  end

  @doc """
  Set the current value of nonce for the specified cipher.
  """
  @spec set_nonce(reference(), :in | :out, non_neg_integer()) :: :ok
  def set_nonce(ref, dir, n) when is_reference(ref) and dir in [:in, :out] and is_integer(n) and n >= 0 do
    Process.put(ref, ChannelPair.set_n(Process.get(ref), dir, n))
    :ok
  end

  @doc """
  """
  @spec get_public_key(reference, :e | :re | :rs | :s) :: nil | Crypto.public_key()
  def get_public_key(ref, key) when is_reference(ref) and key in [:e, :s, :re, :rs] do
    case Map.get(Process.get(ref), key) do
      {public, _} ->
        public
      other ->
        other
    end
  end
end
