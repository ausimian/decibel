defmodule VectorTest do
  use ExUnit.Case

  describe "cacophony vectors" do
    for v <- Jason.decode!(File.read!("test/vectors/cacophony.json"))["vectors"] do
      esc = Macro.escape(v)
      test v["protocol_name"], do: run_test(unquote(esc))
    end
  end

  describe "cacophony psk vectors" do
    for v <- Jason.decode!(File.read!("test/vectors/cacophony-psk.json"))["vectors"] do
      esc = Macro.escape(v)
      test v["protocol_name"], do: run_test(unquote(esc))
    end
  end

  describe "snow vectors" do
    for v <- Jason.decode!(File.read!("test/vectors/snow.json"))["vectors"] do
      esc = Macro.escape(v)
      test v["protocol_name"], do: run_test(unquote(esc))
    end
  end

  describe "noise-c fallback vectors" do
    for v <- Jason.decode!(File.read!("test/vectors/noise-c-fallback.json"))["vectors"] do
      esc = Macro.escape(v)
      test v["name"], do: run_fallback_test(convert_psks(unquote(esc)))
    end
  end

  defp run_fallback_test(%{"fallback" => true, "name" => "Noise_XXfallback_" <> _ = name, "pattern" => "IK"} = vec) do
    # Fallback tests simulate recovery from a failed handshake using `Noise Pipes`.
    # In particular, they show how the ephemeral key in the failed IK handshake
    # is reused by the corresponding XXfallback handshake
    initial_protocol = String.replace(name, "XXfallback", "IK")
    initial_vec =
      vec
      |> Map.put("protocol_name", initial_protocol)
      |> Map.delete("fallback")
    ini = initialize(:ini, initial_vec)
    rsp = initialize(:rsp, initial_vec)

    # First message should fail decryption by the responder
    msg = hd(vec["messages"])
    payload = to_binary(msg["payload"])
    ciphertext = to_binary(msg["ciphertext"])

    assert ciphertext == IO.iodata_to_binary(encrypt(ini, payload))
    try do
      decrypt(rsp, ciphertext)
      flunk("Handshake should fail")
    rescue
      e in Decibel.DecryptionError ->
        re = e.remote_keys[:re]
        # Run the fallback protocol using this ephemeral key
        vec
        |> Map.put("protocol_name", String.replace(initial_protocol, "Noise_IK", "Noise_XXfallback"))
        |> Map.delete("init_remote_static")
        |> Map.update!("messages", &tl/1)
        |> Map.put("resp_remote_ephemeral", Base.encode16(re, case: :lower))
        |> run_test
    end
  end

  defp run_test(vec) when is_map(vec) do
    ini = initialize(:ini, vec)
    rsp = initialize(:rsp, vec)
    oneway = is_oneway?(vec["protocol_name"])

    # If we're running a fallback handshake, the responder goes first
    {w, r} = if vec["fallback"], do: {rsp, ini}, else: {ini, rsp}

    {r1, r2} =
      Enum.reduce(vec["messages"], {w, r}, fn msg, {writer, reader} ->
        payload = to_binary(msg["payload"])
        ciphertext = to_binary(msg["ciphertext"])

        assert ciphertext == IO.iodata_to_binary(encrypt(writer, payload))
        assert payload == IO.iodata_to_binary(decrypt(reader, ciphertext))
        if oneway, do: {writer, reader}, else: {reader, writer}
      end)

    if Enum.all?([r1, r2], &Decibel.is_handshake_complete?/1) do
      if hh_hex = vec["handshake_hash"] do
        hh = to_binary(hh_hex)
        assert hh == Decibel.get_handshake_hash(r1)
        assert hh == Decibel.get_handshake_hash(r2)

        Decibel.rekey(r1, :out)
        Decibel.rekey(r2, :in)
        msg = "Should work after rekey"
        assert msg == Decibel.decrypt(r2, Decibel.encrypt(r1, msg))
      end
    end

    Decibel.close(r1)
    Decibel.close(r2)
  end

  defp encrypt(ref, plaintext) do
    if Decibel.is_handshake_complete?(ref) do
      Decibel.encrypt(ref, plaintext)
    else
      Decibel.handshake_encrypt(ref, plaintext)
    end
  end

  defp decrypt(ref, plaintext) do
    if Decibel.is_handshake_complete?(ref) do
      Decibel.decrypt(ref, plaintext)
    else
      Decibel.handshake_decrypt(ref, plaintext)
    end
  end

  defp initialize(role, vec) do
    protocol_name = vec["protocol_name"]
    curve = decode_dh(protocol_name)
    prefix = if role == :ini, do: "init_", else: "resp_"

    keys =
      for {key, name} <- [e: "ephemeral", s: "static", rs: "remote_static", re: "remote_ephemeral", prologue: "prologue", psks: "psks"],
          reduce: %{} do
        keys ->
          case Map.get(vec, prefix <> name) do
            nil ->
              keys

            keyval when is_binary(keyval) ->
              Map.put(keys, key, to_key(key, curve, to_binary(keyval)))

            keyvals when is_list(keyvals) ->
              Map.put(keys, key, Enum.map(keyvals, &to_binary/1))
          end
      end

    opts = if vec["fallback"], do: [swap: :rsp], else: [swap: :ini]
    Decibel.new(protocol_name, role, keys, opts)
  end

  defp is_oneway?(protocol_name) do
    case Decibel.Utility.parse_protocol_name(protocol_name) do
      {{name, _}, _, _, _} -> name in ["N", "K", "X"]
    end
  end

  defp decode_dh(protocol_name) do
    protocol_name
    |> Decibel.Utility.parse_protocol_name()
    |> elem(1)
  end

  defp to_key(key, curve, bytes) when key in [:e, :s] do
    :crypto.generate_key(:ecdh, curve, bytes)
  end

  defp to_key(_, _, bytes), do: bytes

  defp to_binary(hex_string) do
    Base.decode16!(hex_string, case: :lower)
  end

  defp convert_psks(vec) do
    # The vectors from noise-c need to be converted to the same form as
    # cacophony and snow, which means renaming their psk fields and making
    # their values lists
    vec
    |> convert_psk("init_psk")
    |> convert_psk("resp_psk")
  end

  defp convert_psk(vec, field) do
    case Map.pop(vec, field) do
      {nil, _} -> vec
      {val, vec2} when is_binary(val) ->
        Map.put(vec2, field <> "s", [val])
    end
  end

end
