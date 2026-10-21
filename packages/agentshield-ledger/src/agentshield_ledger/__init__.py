"""Agent Shield tamper-evident audit ledger.

`agentshield_ledger.verify` is the zero-dependency core (hash chain,
Merkle tree, Ed25519 verification, the offline `agentshield-verify` CLI).
This top-level package adds the `cryptography`-backed checkpoint signer,
the in-process `Ledger` orchestrator, external anchoring, and async
SQLAlchemy persistence.
"""

from agentshield_ledger.anchoring import Anchor, FileAnchor, InMemoryAnchor
from agentshield_ledger.checkpoint import Checkpoint, sign_checkpoint, verify_checkpoint
from agentshield_ledger.ledger import Ledger

__all__ = [
    "Anchor",
    "FileAnchor",
    "InMemoryAnchor",
    "Checkpoint",
    "sign_checkpoint",
    "verify_checkpoint",
    "Ledger",
]
