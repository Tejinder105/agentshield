"""The zero-dependency core of the Agent Shield ledger.

Every module in this subpackage -- `canonical`, `hashchain`, `merkle`,
`ed25519_pure`, and `cli` -- imports *nothing* beyond the Python standard
library. This is deliberate: an auditor verifying a ledger export should
not have to trust, or even install, the server's own dependency tree
(which includes the much larger `cryptography` package used for signing).
Copy this subpackage anywhere a bare `python3` interpreter runs and
`cli.py` works unmodified.

The rest of `agentshield_ledger` (the live `Ledger` service, checkpoint
signing, Postgres persistence) depends on `cryptography` and `sqlalchemy`
and imports freely *from* this subpackage -- the dependency direction only
ever goes one way.
"""
