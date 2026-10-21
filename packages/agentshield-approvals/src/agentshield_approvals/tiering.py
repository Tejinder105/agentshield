"""Consequence-based approval tiering.

Cedar's own authorization decision (in `agentshield-policy`) is binary:
allow or deny a call given its typed arguments. It has no way to express
"allowed, but only with a human's sign-off first" -- that is a *tiering*
decision layered on top of, not inside, the policy engine. This module is
that layer: it classifies a (tool, arguments) pair into an `ApprovalTier`,
and `ConsequenceTieringPolicy.requires_approval` is the hook
`agentshield_gateway.pipeline.DecisionPipeline` consults at its step 4.

`ConsequenceTieringPolicy` is never imported by `agentshield-gateway`, nor
does this package depend on it: `requires_approval(tool_name, arguments)
-> bool` satisfies the gateway's `ApprovalPolicy` Protocol purely
structurally. Keeping the dependency one-directional (or, here, absent
entirely) is what lets each package in this repository stay independently
testable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

Predicate = Callable[[Mapping[str, Any]], bool]


class ApprovalTier(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class TierRule:
    tier: ApprovalTier
    predicate: Predicate | None = None  # None matches unconditionally

    def matches(self, arguments: Mapping[str, Any]) -> bool:
        return self.predicate is None or self.predicate(arguments)


@dataclass(slots=True)
class ConsequenceTieringPolicy:
    """Rules are checked in registration order per tool; the first
    matching rule's tier wins. A tool with no matching rule (including one
    never registered at all) gets `default_tier`.
    """

    default_tier: ApprovalTier = ApprovalTier.NONE
    rules: dict[str, list[TierRule]] = field(default_factory=dict)

    def register(
        self, tool_name: str, tier: ApprovalTier, *, when: Predicate | None = None
    ) -> None:
        self.rules.setdefault(tool_name, []).append(TierRule(tier=tier, predicate=when))

    def tier_for(self, tool_name: str, arguments: Mapping[str, Any]) -> ApprovalTier:
        for rule in self.rules.get(tool_name, ()):
            if rule.matches(arguments):
                return rule.tier
        return self.default_tier

    def requires_approval(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
        return self.tier_for(tool_name, arguments) is not ApprovalTier.NONE
