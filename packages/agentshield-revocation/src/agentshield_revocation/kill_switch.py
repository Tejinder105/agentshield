"""The kill switch: the single human-facing action that stops new damage.

It does exactly two things, in order, and nothing else:

1. Bump an epoch (global, or one session) in the `EpochStore` -- this is
   what actually revokes capabilities, and it is what gives revocation its
   bounded latency: the *next* call the gateway's pipeline evaluates for an
   affected session is denied at step 2, the instant the bump finishes.
2. Drain the pending-approval queue (global trigger only -- see below), so
   a human cannot approve something mid-incident that the kill switch was
   just thrown to stop.

It deliberately does **not** try to cancel calls already past step 7 of
the gateway's pipeline (already dispatching) -- that is a correctness
trade a reference monitor cannot safely make (killing an in-flight write
can itself be destructive), and it is exactly why `blast_radius` exists:
to report, after the fact and from the tamper-evident ledger alone, what
slipped through during the exposure window.

Session-scoped triggers (`trigger_session`) deliberately do *not* drain
the approval queue, since that queue has no per-session index in
`agentshield-approvals` and draining it globally for a single-session
incident would deny unrelated, uninvolved sessions' pending approvals too.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from agentshield_revocation.epoch_store import EpochStore


class ApprovalDrain(Protocol):
    async def drain_pending(self) -> list[Any]:
        """Satisfied structurally by `agentshield_approvals.service.
        ApprovalService.drain_pending` -- this package does not import or
        depend on `agentshield-approvals`.
        """
        ...


class LedgerSink(Protocol):
    def append(self, event_type: str, payload: dict[str, Any]) -> Any:
        """Satisfied structurally by `agentshield_ledger.ledger.Ledger`."""
        ...


@dataclass(frozen=True, slots=True)
class KillSwitchResult:
    scope: str  # "global" | "session"
    reason: str
    triggered_at: int
    session_id: str | None
    new_global_epoch: int | None
    new_session_epoch: int | None
    drained_approvals: tuple[Any, ...]


@dataclass(slots=True)
class KillSwitch:
    epoch_store: EpochStore
    approval_drain: ApprovalDrain | None = None
    ledger: LedgerSink | None = None
    clock: Callable[[], float] = time.time

    async def trigger_global(self, *, reason: str) -> KillSwitchResult:
        """Invalidate every capability in every session, then drain every
        pending approval request. Idempotent in effect (a second call just
        bumps the epoch again and finds nothing left to drain).
        """
        triggered_at = int(self.clock())
        new_epoch = await self.epoch_store.bump_global_epoch()
        drained = list(await self.approval_drain.drain_pending()) if self.approval_drain else []
        if self.ledger is not None:
            self.ledger.append(
                "kill_switch_triggered",
                {
                    "scope": "global",
                    "reason": reason,
                    "new_global_epoch": new_epoch,
                    "drained_count": len(drained),
                },
            )
        return KillSwitchResult(
            scope="global",
            reason=reason,
            triggered_at=triggered_at,
            session_id=None,
            new_global_epoch=new_epoch,
            new_session_epoch=None,
            drained_approvals=tuple(drained),
        )

    async def trigger_session(self, session_id: str, *, reason: str) -> KillSwitchResult:
        """Invalidate every capability in exactly `session_id`."""
        triggered_at = int(self.clock())
        new_epoch = await self.epoch_store.bump_session_epoch(session_id)
        if self.ledger is not None:
            self.ledger.append(
                "kill_switch_triggered",
                {
                    "scope": "session",
                    "session_id": session_id,
                    "reason": reason,
                    "new_session_epoch": new_epoch,
                },
            )
        return KillSwitchResult(
            scope="session",
            reason=reason,
            triggered_at=triggered_at,
            session_id=session_id,
            new_global_epoch=None,
            new_session_epoch=new_epoch,
            drained_approvals=(),
        )
