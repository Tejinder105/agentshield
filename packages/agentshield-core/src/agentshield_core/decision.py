"""The Policy Decision Point's output type.

A `Decision` is the single value the rest of the system is allowed to act on.
It is deliberately a closed, exhaustively-matched type: there is no "maybe"
outcome that silently defaults to allow, and every `Decision` records which
pipeline stage produced it for audit and explainability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DecisionKind(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ObligationKind(StrEnum):
    """A condition that must be fulfilled at or after dispatch time, even
    though the decision itself was ALLOW or REQUIRE_APPROVAL -- e.g. "redact
    these fields before logging" or "record this as uncertain if the call
    times out".
    """

    REDACT_FIELDS = "REDACT_FIELDS"
    ATTACH_CAVEAT = "ATTACH_CAVEAT"
    RECORD_AS_UNCERTAIN_ON_TIMEOUT = "RECORD_AS_UNCERTAIN_ON_TIMEOUT"
    RAISE_APPROVAL_TIER = "RAISE_APPROVAL_TIER"
    # Carries a `agentshield_policy.subsumption.SubsumptionReport` (as a plain
    # dict, so `agentshield-core` never has to depend on `agentshield-policy`)
    # explaining *why* a monotonic-confinement policy update could not be
    # auto-applied, for a human reviewer -- e.g. the console's policy editor --
    # to inspect alongside the REQUIRE_APPROVAL decision.
    RECORD_SUBSUMPTION_EVIDENCE = "RECORD_SUBSUMPTION_EVIDENCE"


@dataclass(frozen=True, slots=True)
class Obligation:
    kind: ObligationKind
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Decision:
    kind: DecisionKind
    reason: str
    obligations: tuple[Obligation, ...] = ()
    stage: str = ""

    @property
    def is_allowed(self) -> bool:
        return self.kind is DecisionKind.ALLOW

    @property
    def is_denied(self) -> bool:
        return self.kind is DecisionKind.DENY

    @property
    def needs_approval(self) -> bool:
        return self.kind is DecisionKind.REQUIRE_APPROVAL

    @staticmethod
    def allow(reason: str, stage: str, obligations: tuple[Obligation, ...] = ()) -> Decision:
        return Decision(
            kind=DecisionKind.ALLOW, reason=reason, obligations=obligations, stage=stage
        )

    @staticmethod
    def deny(reason: str, stage: str) -> Decision:
        return Decision(kind=DecisionKind.DENY, reason=reason, stage=stage)

    @staticmethod
    def require_approval(
        reason: str, stage: str, obligations: tuple[Obligation, ...] = ()
    ) -> Decision:
        return Decision(
            kind=DecisionKind.REQUIRE_APPROVAL, reason=reason, obligations=obligations, stage=stage
        )


# A deny always wins: this total order lets the pipeline fold a list of
# per-stage decisions into one final verdict without ad hoc if/elif chains.
_SEVERITY = {DecisionKind.ALLOW: 0, DecisionKind.REQUIRE_APPROVAL: 1, DecisionKind.DENY: 2}


def most_severe(decisions: tuple[Decision, ...]) -> Decision:
    """Combine multiple stage decisions into one, DENY beating
    REQUIRE_APPROVAL beating ALLOW. Used so that, e.g., a Cedar-level ALLOW
    plus a label-ceiling REQUIRE_APPROVAL correctly yields REQUIRE_APPROVAL
    overall.
    """
    if not decisions:
        return Decision.deny("no stages evaluated", stage="pipeline")
    return max(decisions, key=lambda d: _SEVERITY[d.kind])
