"""Per-capability spend and call quotas.

A capability that can be used an unbounded number of times, or to move an
unbounded amount of money, is not least-privilege -- it is a time-boxed
blank check. `QuotaStore` is the counterpart of `Capability.caveats` for
the two limits caveats cannot express on their own: they are evaluated
against *this call's arguments* only, and they have no memory of how the
capability has already been used.

Quotas are consumed only when a call is authorized to proceed (see
`agentshield_gateway.pipeline`), never on a denial, so a flood of
rejected calls cannot burn a session's remaining budget. A dispatched-
but-unconfirmed call *does* consume quota: the side effect may have
happened, and charging the budget for an uncertain outcome is the
fail-closed choice.

Spend is always an integer (minor currency units, token counts, ...),
never a float -- the same reason the ledger rejects floats.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Quota:
    """The two limits a capability may carry. `None` on either field
    means that axis is unlimited.
    """

    max_calls: int | None = None
    max_spend: int | None = None
    spend_arg: str = "amount"


@dataclass(slots=True)
class QuotaStore:
    """In-memory per-capability usage. A production deployment can back
    this with Redis the same way the revocation epoch store is backed;
    the interface is deliberately just `check` / `consume` so that swap
    does not touch the pipeline.
    """

    quotas: dict[str, Quota] = field(default_factory=dict)
    calls_used: dict[str, int] = field(default_factory=dict)
    spend_used: dict[str, int] = field(default_factory=dict)

    def register(self, capability_id: str, quota: Quota) -> None:
        self.quotas[capability_id] = quota

    def _spend_of(self, quota: Quota, arguments: dict[str, Any]) -> int:
        raw = arguments.get(quota.spend_arg, 0)
        if isinstance(raw, bool) or not isinstance(raw, int):
            return 0
        return raw

    def check(self, capability_id: str, arguments: dict[str, Any]) -> str | None:
        """Return a denial reason if this call would exceed a registered
        quota, or `None` if the call is within budget (or the capability
        has no quota at all).
        """
        quota = self.quotas.get(capability_id)
        if quota is None:
            return None
        if quota.max_calls is not None:
            used = self.calls_used.get(capability_id, 0)
            if used + 1 > quota.max_calls:
                return (
                    f"capability {capability_id} has exhausted its call quota ({quota.max_calls})"
                )
        if quota.max_spend is not None:
            used = self.spend_used.get(capability_id, 0)
            this_call = self._spend_of(quota, arguments)
            if used + this_call > quota.max_spend:
                return (
                    f"capability {capability_id} has exhausted its spend quota ({quota.max_spend})"
                )
        return None

    def consume(self, capability_id: str, arguments: dict[str, Any]) -> None:
        """Record that an authorized call used this capability. A
        capability with no registered quota is a no-op.
        """
        quota = self.quotas.get(capability_id)
        if quota is None:
            return
        self.calls_used[capability_id] = self.calls_used.get(capability_id, 0) + 1
        self.spend_used[capability_id] = self.spend_used.get(capability_id, 0) + self._spend_of(
            quota, arguments
        )
