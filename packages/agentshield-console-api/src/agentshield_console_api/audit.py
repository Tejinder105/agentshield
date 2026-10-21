"""The audit explorer's data model: a session's ledger entries, with
provenance-path denial explanations surfaced verbatim where the gateway
attached one (see `agentshield_gateway.pipeline.DecisionPipeline._deny`'s
`provenance_path` payload key), plus the overall hash-chain integrity
check that is what makes any of this trustworthy in the first place.

Tamper-evidence is a property of the *whole* chain, not of one session's
slice of it: altering a different session's entry would still break every
subsequent hash, including this session's. `chain_intact` is therefore
always computed over every entry the ledger holds, never over a
session-filtered subset -- filtering happens only afterward, for display.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agentshield_ledger.verify.hashchain import ChainedEntry, verify_chain


@dataclass(frozen=True, slots=True)
class AuditEntryView:
    seq: int
    event_type: str
    payload: dict[str, Any]
    ts: int | None
    entry_hash: str


def session_entries(entries: Sequence[ChainedEntry], session_id: str) -> list[AuditEntryView]:
    """Every ledger entry whose payload names `session_id`, in the
    original append order (`ChainedEntry.seq` ascending, since the ledger
    never reorders).

    A session-scoped kill switch's `kill_switch_triggered` entry *does*
    carry `session_id` and is therefore included; a *global* kill switch's
    entry deliberately does not (see `agentshield_revocation.kill_switch`)
    and is therefore excluded here -- it affects every session, so it is
    not any one session's event to claim.
    """
    return [
        AuditEntryView(
            seq=e.seq,
            event_type=e.entry["event_type"],
            payload=e.entry["payload"],
            ts=e.entry.get("ts"),
            entry_hash=e.entry_hash,
        )
        for e in entries
        if e.entry["payload"].get("session_id") == session_id
    ]


def chain_intact(entries: Sequence[ChainedEntry]) -> bool:
    return verify_chain(list(entries))
