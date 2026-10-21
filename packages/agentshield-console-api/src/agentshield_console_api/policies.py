"""Session-scoped Cedar policy administration for the console's policy
editor and validator.

`PolicyRegistry` is a simple in-memory, session-keyed store of each
session's `(GeneratedSchema, PolicyStore)` pair. In a real multi-worker
deployment this needs the same shared-storage treatment
`agentshield_gateway.session.SessionStore`'s own docstring calls out for
itself; staying in-memory here is this package's explicit, documented
scope boundary, not an oversight -- and it is also why this module never
imports `agentshield-gateway`: the console administers policy state that a
real deployment would back with the same shared store the gateway reads
from, not a second, independent copy of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentshield_confinement.gate import propose_policy_update
from agentshield_core.decision import Decision
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.policies import PolicyStore, PolicyValidationError


class UnknownSessionError(KeyError):
    """Raised when a session has no registered policy yet."""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...] = ()


@dataclass(slots=True)
class SessionPolicy:
    schema: GeneratedSchema
    store: PolicyStore


class PolicyRegistry:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionPolicy] = {}

    def register(
        self, session_id: str, *, schema: GeneratedSchema, policy_text: str
    ) -> SessionPolicy:
        """Register (or completely replace) a session's schema and policy,
        e.g. right after `agentshield_confinement.synthesis.
        synthesize_initial_policy` produced the session's initial policy.

        Unlike `propose_update`, this is an unconditional administrative
        write: it never consults monotonic confinement, since there is no
        previous policy for a *registration* to narrow from.
        """
        store = PolicyStore(policy_text=policy_text, schema=schema)
        session_policy = SessionPolicy(schema=schema, store=store)
        self._sessions[session_id] = session_policy
        return session_policy

    def get(self, session_id: str) -> SessionPolicy | None:
        return self._sessions.get(session_id)

    def validate(self, session_id: str, candidate_policy_text: str) -> ValidationResult:
        """Parse and schema-validate `candidate_policy_text` against the
        session's Cedar schema. A pure read: never applies the candidate,
        and never consults subsumption, so the registry's stored policy is
        untouched regardless of the result.
        """
        session_policy = self._get_or_raise(session_id)
        try:
            PolicyStore(policy_text=candidate_policy_text, schema=session_policy.schema)
        except PolicyValidationError as exc:
            errors = tuple(exc.errors) if exc.errors else (str(exc),)
            return ValidationResult(valid=False, errors=errors)
        return ValidationResult(valid=True)

    def propose_update(self, session_id: str, candidate_policy_text: str) -> Decision:
        """Attempt to apply `candidate_policy_text` through the monotonic-
        confinement gate (`agentshield_confinement.gate.
        propose_policy_update`): a candidate *proven* to narrow the
        session's current action space is applied in place and `ALLOW` is
        returned; a malformed candidate is `DENY`; everything else (a
        proven expansion, or anything subsumption could not prove either
        way) is left unapplied and returned as `REQUIRE_APPROVAL`, carrying
        the full subsumption report for a human reviewer.
        """
        session_policy = self._get_or_raise(session_id)
        return propose_policy_update(
            session_policy.store,
            candidate_policy_text,
            schema=session_policy.schema,
            session_id=session_id,
        )

    def _get_or_raise(self, session_id: str) -> SessionPolicy:
        session_policy = self._sessions.get(session_id)
        if session_policy is None:
            raise UnknownSessionError(session_id)
        return session_policy
