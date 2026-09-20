defmodule Decibel.NonceTest do
  use ExUnit.Case

  @before_final_nonce 2 ** 64 - 3
  @final_usable_nonce 2 ** 64 - 2
  @reserved_nonce 2 ** 64 - 1
  @past_reserved_nonce 2 ** 64

  for {cipher, protocol} <- [
        {"ChaChaPoly", "Noise_NN_25519_ChaChaPoly_BLAKE2s"},
        {"AESGCM", "Noise_NN_448_AESGCM_SHA512"}
      ] do
    test "#{cipher} consumes the final nonce in both transport directions" do
      {ini, rsp} = establish_session(unquote(protocol))

      assert_direction_exhaustion(ini, rsp)
      assert_direction_exhaustion(rsp, ini)

      Decibel.close(ini)
      Decibel.close(rsp)
    end

    test "#{cipher} validates nonce bounds for every channel" do
      {ini, rsp} = establish_session(unquote(protocol))

      for ref <- [ini, rsp], direction <- [:in, :out] do
        assert :ok == Decibel.set_nonce(ref, direction, @before_final_nonce)
        assert @before_final_nonce == Decibel.get_nonce(ref, direction)

        assert :ok == Decibel.set_nonce(ref, direction, @final_usable_nonce)
        assert @final_usable_nonce == Decibel.get_nonce(ref, direction)

        for invalid <- [-1, @reserved_nonce, @past_reserved_nonce, :not_a_nonce] do
          message =
            "Nonce must be an integer from 0 to 18446744073709551614, got: " <>
              inspect(invalid, limit: 10, printable_limit: 50)

          error =
            assert_raise Decibel.NonceError, message, fn ->
              Decibel.set_nonce(ref, direction, invalid)
            end

          assert error.reason == :out_of_range
          assert error.nonce == invalid
          assert error.current_nonce == nil
          assert @final_usable_nonce == Decibel.get_nonce(ref, direction)
        end
      end

      Decibel.close(ini)
      Decibel.close(rsp)
    end

    test "#{cipher} rejects outbound nonce rewinds without changing state" do
      {ini, rsp} = establish_session(unquote(protocol))

      for ref <- [ini, rsp] do
        assert :ok == Decibel.set_nonce(ref, :out, 5)
        assert :ok == Decibel.set_nonce(ref, :out, 5)
        assert 5 == Decibel.get_nonce(ref, :out)

        assert :ok == Decibel.rekey(ref, :out)
        assert 5 == Decibel.get_nonce(ref, :out)

        error =
          assert_raise Decibel.NonceError,
                       "Outbound nonce cannot move backwards from 5 to 4",
                       fn -> Decibel.set_nonce(ref, :out, 4) end

        assert error.reason == :rewind
        assert error.nonce == 4
        assert error.current_nonce == 5
        assert 5 == Decibel.get_nonce(ref, :out)

        for invalid <- [-1, @reserved_nonce, @past_reserved_nonce, :not_a_nonce] do
          error =
            assert_raise Decibel.NonceError, fn ->
              Decibel.set_nonce(ref, :out, invalid)
            end

          assert error.reason == :out_of_range
          assert error.nonce == invalid
          assert error.current_nonce == nil
          assert 5 == Decibel.get_nonce(ref, :out)
        end

        assert :ok == Decibel.set_nonce(ref, :out, @final_usable_nonce)
        _ciphertext = Decibel.encrypt(ref, "final outbound nonce")
        assert @reserved_nonce == Decibel.get_nonce(ref, :out)

        error =
          assert_raise Decibel.NonceError,
                       "Outbound nonce cannot move backwards from 18446744073709551615 to 0",
                       fn -> Decibel.set_nonce(ref, :out, 0) end

        assert error.reason == :rewind
        assert error.nonce == 0
        assert error.current_nonce == @reserved_nonce
        assert @reserved_nonce == Decibel.get_nonce(ref, :out)
      end

      Decibel.close(ini)
      Decibel.close(rsp)
    end
  end

  test "one-way direction validation takes precedence over nonce validation" do
    {rsp_public, _rsp_private} = rsp_static = :crypto.generate_key(:ecdh, :x25519)
    ini = Decibel.new("Noise_N_25519_ChaChaPoly_BLAKE2s", :ini, %{rs: rsp_public})
    rsp = Decibel.new("Noise_N_25519_ChaChaPoly_BLAKE2s", :rsp, %{s: rsp_static})

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    error =
      assert_raise Decibel.TransportDirectionError,
                   "Inbound transport is not permitted by this one-way handshake",
                   fn -> Decibel.set_nonce(ini, :in, @reserved_nonce) end

    assert error.direction == :in
    assert 0 == Decibel.get_nonce(ini, :out)

    Decibel.close(ini)
    Decibel.close(rsp)
  end

  defp assert_direction_exhaustion(sender, recipient) do
    assert :ok == Decibel.set_nonce(sender, :out, @before_final_nonce)
    assert :ok == Decibel.set_nonce(recipient, :in, @before_final_nonce)

    first_ciphertext = Decibel.encrypt(sender, "before final", "aad-before")
    assert "before final" == Decibel.decrypt(recipient, first_ciphertext, "aad-before")
    assert @final_usable_nonce == Decibel.get_nonce(sender, :out)
    assert @final_usable_nonce == Decibel.get_nonce(recipient, :in)

    final_ciphertext = Decibel.encrypt(sender, "final", "aad-final")
    assert "final" == Decibel.decrypt(recipient, final_ciphertext, "aad-final")
    assert @reserved_nonce == Decibel.get_nonce(sender, :out)
    assert @reserved_nonce == Decibel.get_nonce(recipient, :in)

    assert_exhausted(fn -> Decibel.encrypt(sender, "too late") end)
    assert_exhausted(fn -> Decibel.decrypt(recipient, final_ciphertext, "aad-final") end)
    assert @reserved_nonce == Decibel.get_nonce(sender, :out)
    assert @reserved_nonce == Decibel.get_nonce(recipient, :in)
  end

  defp assert_exhausted(operation) do
    error = assert_raise Decibel.NonceError, "Cipher nonce is exhausted", operation
    assert error.reason == :exhausted
    assert error.nonce == @reserved_nonce
    assert error.current_nonce == nil
  end

  defp establish_session(protocol) do
    ini = Decibel.new(protocol, :ini)
    rsp = Decibel.new(protocol, :rsp)

    ini
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(rsp, &1))

    rsp
    |> Decibel.handshake_encrypt()
    |> then(&Decibel.handshake_decrypt(ini, &1))

    {ini, rsp}
  end
end
