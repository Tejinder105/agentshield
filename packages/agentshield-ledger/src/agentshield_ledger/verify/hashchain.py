"""The append-only hash chain.

Each entry's hash commits to the canonical bytes of the entry itself and to
the previous entry's hash, so altering, reordering, or deleting any
historical entry changes every subsequent hash in the chain -- this is the
property a casual reader checks first, before ever reaching for the
heavier Merkle-tree machinery in `merkle.py`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from agentshield_ledger.verify.canonical import canonicalize

GENESIS_HASH = "0" * 64


def compute_entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
    """entry_hash = SHA-256(prev_hash || canonical(entry))."""
    payload = prev_hash.encode("ascii") + canonicalize(entry)
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ChainedEntry:
    seq: int
    entry: dict[str, Any]
    prev_hash: str
    entry_hash: str

    @staticmethod
    def first(entry: dict[str, Any]) -> ChainedEntry:
        return ChainedEntry(
            seq=0,
            entry=entry,
            prev_hash=GENESIS_HASH,
            entry_hash=compute_entry_hash(GENESIS_HASH, entry),
        )

    def extend(self, entry: dict[str, Any]) -> ChainedEntry:
        return ChainedEntry(
            seq=self.seq + 1,
            entry=entry,
            prev_hash=self.entry_hash,
            entry_hash=compute_entry_hash(self.entry_hash, entry),
        )


def verify_chain(entries: list[ChainedEntry]) -> bool:
    """Recompute every hash in sequence. True iff the chain is internally
    consistent from the genesis hash onward.
    """
    if not entries:
        return True
    expected_prev = GENESIS_HASH
    for e in entries:
        if e.prev_hash != expected_prev:
            return False
        if compute_entry_hash(e.prev_hash, e.entry) != e.entry_hash:
            return False
        expected_prev = e.entry_hash
    return True
