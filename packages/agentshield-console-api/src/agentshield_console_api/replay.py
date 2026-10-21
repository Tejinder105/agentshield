"""Deterministic session replay, from the tamper-evident ledger alone.

"Deterministic" here is a claim about *reconstruction*, not re-execution:
replay never re-runs Cedar, re-derives labels, or re-checks a receipt --
every decision the pipeline ever reached for a session was already
recorded, in order, in the ledger at the moment it was reached. Replaying
a session means reconstructing that exact recorded sequence and proving,
via the hash chain, that it has not been altered since -- which is the
only kind of "exact reproduction" a reference monitor can honestly offer
without re-creating every historical version of a session's policy (which,
under monotonic confinement, can legitimately change mid-session).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from agentshield_ledger.verify.hashchain import ChainedEntry

from agentshield_console_api.audit import AuditEntryView, chain_intact, session_entries


@dataclass(frozen=True, slots=True)
class SessionReplay:
    session_id: str
    chain_intact: bool
    steps: tuple[AuditEntryView, ...]

    @property
    def final_decision(self) -> str | None:
        """The `decision` field of the last `"decision"`-type step, if
        any -- what the session's last mediated tool call was ultimately
        decided to be (`ALLOW` / `DENY` / `REQUIRE_APPROVAL`).
        """
        for step in reversed(self.steps):
            if step.event_type == "decision":
                decision = step.payload.get("decision")
                return str(decision) if decision is not None else None
        return None


def replay_session(entries: Sequence[ChainedEntry], session_id: str) -> SessionReplay:
    """Reconstruct `session_id`'s full decision timeline from `entries`.

    `chain_intact` is checked over *all* of `entries`, not just this
    session's slice -- see `agentshield_console_api.audit`'s module
    docstring for why that is the only sound way to check it.
    """
    return SessionReplay(
        session_id=session_id,
        chain_intact=chain_intact(entries),
        steps=tuple(session_entries(entries, session_id)),
    )
