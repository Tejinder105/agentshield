"""External anchoring: publishing checkpoints somewhere the ledger's own
operator cannot silently rewrite.

Local hash-chaining and Merkle-signing make tampering *detectable* to
someone who already holds an honest copy of history. External anchoring is
what makes a rewrite *provable* to a third party: once a checkpoint has
left the operator's control, un-publishing it is no longer possible, so a
later rewrite that contradicts an already-anchored checkpoint is caught.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from agentshield_ledger.checkpoint import Checkpoint


class Anchor(Protocol):
    def publish(self, checkpoint: Checkpoint) -> str:
        """Publish a checkpoint externally. Returns an opaque reference
        (a URL, object key, or transaction id) recorded alongside it.
        """
        ...


class FileAnchor:
    """The simplest possible anchor: append each checkpoint as one JSON
    line to a local file.

    This is NOT a substitute for a real external anchor (a separate object
    store with write-once semantics, a witness network, or a public
    Certificate-Transparency-style log) in production -- it exists so the
    `Anchor` interface and its call sites are exercised and testable
    without standing up external infrastructure. Swap in a real
    implementation before relying on this for the "the operator cannot
    un-publish it" property the threat model requires.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def publish(self, checkpoint: Checkpoint) -> str:
        line = json.dumps(
            {
                "merkle_root": checkpoint.merkle_root_hex,
                "tree_size": checkpoint.tree_size,
                "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
                "timestamp": checkpoint.timestamp,
                "signature": checkpoint.signature_hex,
            },
            sort_keys=True,
        )
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        return f"file://{self._path}#{checkpoint.tree_size}"


class InMemoryAnchor:
    """An anchor that just remembers what was published, for tests."""

    def __init__(self) -> None:
        self.published: list[Checkpoint] = []

    def publish(self, checkpoint: Checkpoint) -> str:
        self.published.append(checkpoint)
        return f"memory://{len(self.published) - 1}"
