"""The lethal-trifecta invariant.

Per the Frontier Model Forum framing, an agent is only dangerous when it
simultaneously (a) is exposed to untrusted content, (b) has access to private
data, and (c) holds an external communication channel. Agent Shield tracks
these three booleans per session and treats acquiring the third leg -- while
the other two are already present -- as a denial, not a warning.

This converts a vague best practice ("don't let agents read untrusted data
AND touch secrets AND talk to the outside world all at once") into a checked
runtime invariant evaluated on every tool call.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class TrifectaLeg(StrEnum):
    UNTRUSTED_INPUT = "untrusted_input"
    PRIVATE_DATA = "private_data"
    EXTERNAL_COMMUNICATION = "external_communication"


_ALL_LEGS = frozenset(TrifectaLeg)


@dataclass(frozen=True, slots=True)
class TrifectaState:
    """Immutable snapshot of which trifecta legs a session has acquired."""

    untrusted_input: bool = False
    private_data: bool = False
    external_communication: bool = False

    def has(self, leg: TrifectaLeg) -> bool:
        return bool(getattr(self, leg.value))

    def acquired_legs(self) -> frozenset[TrifectaLeg]:
        return frozenset(leg for leg in TrifectaLeg if self.has(leg))

    def would_complete_trifecta(self, acquiring: TrifectaLeg) -> bool:
        """True if acquiring `acquiring` on top of the current state would
        give the session all three legs at once. Already-held legs are a
        no-op: acquiring something you already have cannot newly complete
        the trifecta.
        """
        if self.has(acquiring):
            return False
        projected = self.acquired_legs() | {acquiring}
        return projected == _ALL_LEGS

    def with_leg_acquired(self, leg: TrifectaLeg) -> TrifectaState:
        """Return a new state with `leg` acquired.

        This method only tracks state; it does not enforce anything.
        Callers in the enforcement path MUST call `would_complete_trifecta`
        and deny *before* ever calling this, otherwise the invariant becomes
        advisory rather than checked.
        """
        return replace(self, **{leg.value: True})

    def describe(self) -> str:
        legs = ", ".join(leg.value for leg in self.acquired_legs()) or "none"
        return f"trifecta legs held: {legs}"
