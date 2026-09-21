# The session tests assert on messages from a spawned owner process that first
# generates a keypair and initialises a handshake. ExUnit's 100ms default is
# marginal for that on a loaded CI runner, and `mix precommit` runs in the
# release workflow, so a flake there aborts a publish.
ExUnit.start(assert_receive_timeout: 500)
