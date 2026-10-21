"""Macaroon-style attenuating capability tokens.

A `Capability` grants permission to call a specific tool, constrained by a
set of `Caveat`s. Caveats can only be *added* -- `attenuate()` always returns
a strictly narrower capability than its input, never a wider one. This gives
sub-agent delegation a provable property: a derived capability cannot exceed
its parent's effective permission, no matter how many times it is attenuated
or re-delegated down a chain of sub-agents.

Capabilities are also epoch-bound and short-lived (TTL), which is what gives
emergency revocation (see `agentshield-revocation`) bounded latency: even a
capability a revocation broadcast somehow missed will self-expire shortly
after.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Predicate = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True, slots=True)
class Caveat:
    """A single restriction on a capability's use.

    `description` is the human/audit-readable form; `predicate` is evaluated
    against the proposed tool-call arguments at authorization time. A
    capability is usable for a given call only if *every* caveat's predicate
    returns True for that call's arguments.
    """

    description: str
    predicate: Predicate

    def __call__(self, args: dict[str, Any]) -> bool:
        return self.predicate(args)


def arg_equals(key: str, value: Any) -> Caveat:
    return Caveat(description=f"{key} == {value!r}", predicate=lambda args: args.get(key) == value)


def arg_in(key: str, allowed: tuple[Any, ...]) -> Caveat:
    return Caveat(
        description=f"{key} in {allowed!r}", predicate=lambda args: args.get(key) in allowed
    )


def arg_matches_prefix(key: str, prefix: str) -> Caveat:
    def _predicate(args: dict[str, Any]) -> bool:
        candidate = args.get(key)
        return isinstance(candidate, str) and candidate.startswith(prefix)

    return Caveat(description=f"{key} startswith {prefix!r}", predicate=_predicate)


def arg_at_most(key: str, maximum: float) -> Caveat:
    def _predicate(args: dict[str, Any]) -> bool:
        candidate = args.get(key)
        return isinstance(candidate, (int, float)) and candidate <= maximum

    return Caveat(description=f"{key} <= {maximum}", predicate=_predicate)


@dataclass(frozen=True, slots=True)
class Capability:
    """An attenuating, epoch-bound, time-limited grant to call one tool."""

    capability_id: str
    session_id: str
    tool_name: str
    caveats: tuple[Caveat, ...]
    epoch: int
    expires_at: float  # unix timestamp
    parent_id: str | None = None

    @staticmethod
    def mint(
        session_id: str,
        tool_name: str,
        epoch: int,
        ttl_seconds: float,
        caveats_: tuple[Caveat, ...] = (),
    ) -> Capability:
        """Create a brand-new, root capability with no parent."""
        return Capability(
            capability_id=str(uuid.uuid4()),
            session_id=session_id,
            tool_name=tool_name,
            caveats=caveats_,
            epoch=epoch,
            expires_at=time.time() + ttl_seconds,
            parent_id=None,
        )

    def attenuate(self, *extra_caveats: Caveat, ttl_seconds: float | None = None) -> Capability:
        """Return a strictly narrower capability: the union of this
        capability's caveats and the new ones. The expiry can only ever move
        earlier, never later, than the parent's.
        """
        new_expiry = self.expires_at
        if ttl_seconds is not None:
            new_expiry = min(self.expires_at, time.time() + ttl_seconds)
        return Capability(
            capability_id=str(uuid.uuid4()),
            session_id=self.session_id,
            tool_name=self.tool_name,
            caveats=self.caveats + tuple(extra_caveats),
            epoch=self.epoch,
            expires_at=new_expiry,
            parent_id=self.capability_id,
        )

    def derive_for_subagent(
        self,
        sub_session_id: str,
        *extra_caveats: Caveat,
        ttl_seconds: float | None = None,
    ) -> Capability:
        """Delegate to a sub-agent. The result is an attenuation bound to a
        new session id; by construction it can never exceed this
        capability's permissions, however many hops of delegation follow.
        """
        attenuated = self.attenuate(*extra_caveats, ttl_seconds=ttl_seconds)
        return Capability(
            capability_id=attenuated.capability_id,
            session_id=sub_session_id,
            tool_name=attenuated.tool_name,
            caveats=attenuated.caveats,
            epoch=attenuated.epoch,
            expires_at=attenuated.expires_at,
            parent_id=self.capability_id,
        )

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def is_current_epoch(self, current_epoch: int) -> bool:
        return self.epoch == current_epoch

    def permits(
        self,
        args: dict[str, Any],
        *,
        now: float | None = None,
        current_epoch: int | None = None,
    ) -> bool:
        """True if this capability authorizes a call with these arguments
        right now, under the current revocation epoch.
        """
        if self.is_expired(now):
            return False
        if current_epoch is not None and not self.is_current_epoch(current_epoch):
            return False
        return all(caveat(args) for caveat in self.caveats)

    def caveat_count(self) -> int:
        """Used by property tests to assert attenuation never decreases
        the number of active constraints.
        """
        return len(self.caveats)
