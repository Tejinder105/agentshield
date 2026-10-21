"""The Ledger: append-only, hash-chained entries, batched into Merkle trees
with signed, externally-anchorable checkpoints.

This is the service-facing API other Agent Shield packages (the gateway,
approvals, revocation) call. It is intentionally the one place that mixes
the zero-dependency primitives in `agentshield_ledger.verify` with the
`cryptography`-backed signing in `agentshield_ledger.checkpoint` -- every
other module in `verify/` stays stdlib-only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentshield_ledger.anchoring import Anchor
from agentshield_ledger.checkpoint import (
    GENESIS_CHECKPOINT_HASH,
    Checkpoint,
    checkpoint_hash,
    sign_checkpoint,
)
from agentshield_ledger.verify.canonical import canonicalize
from agentshield_ledger.verify.hashchain import ChainedEntry
from agentshield_ledger.verify.merkle import MerkleTree


@dataclass(slots=True)
class Ledger:
    """An in-process, append-only ledger.

    Persistence (Postgres) is layered on top via `agentshield_ledger.store`;
    this class holds the hashing/batching/signing logic over an in-memory
    entry list exactly once, so the live service and the test suite share
    one implementation rather than two that could drift apart.
    """

    signing_key: Ed25519PrivateKey
    anchor: Anchor | None = None
    entries: list[ChainedEntry] = field(default_factory=list)
    checkpoints: list[Checkpoint] = field(default_factory=list)

    def append(self, event_type: str, payload: dict[str, Any]) -> ChainedEntry:
        """Append one event. There is no corresponding "update" or
        "delete" method, by design -- see docs/threat-model.md invariant 7.

        Stamps a whole-second integer Unix timestamp (`ts`) -- never a
        float, since `canonicalize` rejects floats by design (see
        `agentshield_ledger.verify.canonical`) -- so downstream consumers
        (notably `agentshield-revocation`'s blast-radius report) can run
        time-windowed queries over the ledger without needing a second,
        separate index.
        """
        entry = {"event_type": event_type, "payload": payload, "ts": int(time.time())}
        chained = self.entries[-1].extend(entry) if self.entries else ChainedEntry.first(entry)
        self.entries.append(chained)
        return chained

    def checkpoint_now(self) -> Checkpoint:
        """Build a Merkle tree over every entry so far, sign its root, and
        record and (if an anchor is configured) publish the checkpoint.
        """
        leaves = [canonicalize(e.entry) for e in self.entries]
        tree = MerkleTree.build(leaves)
        prev_hash = (
            checkpoint_hash(self.checkpoints[-1]) if self.checkpoints else GENESIS_CHECKPOINT_HASH
        )
        cp = sign_checkpoint(
            self.signing_key,
            merkle_root=tree.root,
            tree_size=tree.size,
            prev_checkpoint_hash=prev_hash,
            timestamp=int(time.time()),
        )
        self.checkpoints.append(cp)
        if self.anchor is not None:
            self.anchor.publish(cp)
        return cp

    def export(self) -> dict[str, Any]:
        """A full, self-contained export suitable for offline verification
        by `agentshield_ledger.verify.cli`.
        """
        return {
            "entries": [
                {
                    "seq": e.seq,
                    "entry": e.entry,
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                }
                for e in self.entries
            ],
            "checkpoints": [
                {
                    "merkle_root": cp.merkle_root_hex,
                    "tree_size": cp.tree_size,
                    "prev_checkpoint_hash": cp.prev_checkpoint_hash,
                    "timestamp": cp.timestamp,
                    "signature": cp.signature_hex,
                }
                for cp in self.checkpoints
            ],
        }
