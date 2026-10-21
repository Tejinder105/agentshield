"""Pluggable boundaries the decision pipeline consults at steps 1, 2, 4, and
7, with safe, explicitly fail-closed defaults so the gateway is fully
functional and testable *before* `agentshield-approvals` and
`agentshield-revocation` exist.

Each `Protocol` here is the actual seam a production deployment wires a
real implementation into:

- `PrincipalResolver` -> a verified-identity layer (bearer token, mTLS).
- `EpochSource` -> `agentshield-revocation`'s epoch store (step 2).
- `ApprovalPolicy` -> `agentshield-approvals`'s consequence-tiering engine
  (step 4's approval-tiering extension).
- `ReceiptVerifier` -> `agentshield-approvals`'s Ed25519 receipt verifier
  (step 7).

None of the defaults below are hacks to "make it compile": each one is the
most defensible behavior available with no real backing service, and each
is picked specifically so that *replacing it later changes nothing about
the pipeline's call sites* -- only the collaborator passed into
`DecisionPipeline.__init__` changes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class PrincipalResolver(Protocol):
    def resolve(self, raw_context: Mapping[str, Any]) -> str | None:
        """Return a verified principal identity, or None if unresolvable.
        Pipeline step 1 denies whenever this returns None.
        """
        ...


class KeyPrincipalResolver:
    """Looks up a principal under any of `keys` in `raw_context`, with a
    case-insensitive fallback so it works equally for an HTTP
    `Headers`-like mapping (`x-agent-shield-principal`) and a plain dict
    (`principal`). This is intentionally *not* an authentication system --
    it trusts whatever the transport layer already put in `raw_context`.
    A production deployment should populate that value from a verified
    bearer token or mTLS client certificate upstream of the gateway, and
    this resolver's job becomes "read the already-verified identity," not
    "verify it."
    """

    def __init__(self, keys: tuple[str, ...] = ("x-agent-shield-principal", "principal")) -> None:
        self._keys = keys

    def resolve(self, raw_context: Mapping[str, Any]) -> str | None:
        for key in self._keys:
            value = raw_context.get(key)
            if value is None:
                for actual_key, actual_value in raw_context.items():
                    if isinstance(actual_key, str) and actual_key.lower() == key.lower():
                        value = actual_value
                        break
            if isinstance(value, str) and value:
                return value
        return None


class EpochSource(Protocol):
    async def current_epoch(self, session_id: str) -> int:
        """The current revocation epoch for `session_id`. Pipeline step 2
        denies whenever a capability's own epoch does not match this.

        Deliberately a coroutine, for the same reason `ReceiptVerifier.verify`
        is: a real implementation (`agentshield-revocation`'s epoch store)
        is backed by Redis in production, and that is I/O.
        """
        ...


class ZeroEpochSource:
    """Every session is always at epoch 0: equivalent to "no kill switch has
    ever been thrown." Correct and safe in the absence of
    `agentshield-revocation` -- it changes nothing about which calls are
    allowed, it just means revocation itself is not wired up yet. Replacing
    this with a real epoch store is purely additive: epoch mismatches start
    being caught, nothing that was denied before becomes newly denied.
    """

    async def current_epoch(self, session_id: str) -> int:  # noqa: ARG002
        return 0


class ApprovalPolicy(Protocol):
    def requires_approval(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
        """True if this call must carry a verified human-approval receipt
        before it may dispatch, regardless of what Cedar allows. Consulted
        as part of pipeline step 4, since Cedar's own decision is binary
        allow/deny and cannot express "allowed, but only with sign-off."
        """
        ...


class NeverRequiresApproval:
    """No tool is consequence-tiered. Fail-*open* with respect to the
    approval requirement specifically (every call that Cedar allows
    proceeds without a receipt) -- but this is the correct default in the
    absence of `agentshield-approvals`: there is no tiering policy to
    consult yet, so asserting one trivially would be inventing a
    requirement nobody configured. Overall fail-closed-ness is unaffected,
    since Cedar (step 4) and every other stage still must independently
    allow the call.
    """

    def requires_approval(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:  # noqa: ARG002
        return False


class ReceiptVerifier(Protocol):
    async def verify(
        self, receipt: Any, *, session_id: str, tool_name: str, arguments: Mapping[str, Any]
    ) -> bool:
        """True iff `receipt` is a valid, unexpired, unused, correctly
        bound approval for exactly this call. Consulted at pipeline step 7,
        only when some earlier stage returned REQUIRE_APPROVAL.

        Deliberately a coroutine: a real implementation (see
        `agentshield-approvals`'s `ApprovalService.verify`) must atomically
        claim the receipt's nonce against a shared store (Redis in
        production) to enforce single-use, which is I/O and must not block
        the event loop.
        """
        ...


class RejectAllReceiptVerifier:
    """No receipt is ever valid. This is fail-*closed*: until
    `agentshield-approvals` provides a real Ed25519 verifier, any call that
    reaches step 7 (i.e., something upstream decided it needs human
    sign-off) is denied outright rather than silently let through. Unlike
    `NeverRequiresApproval`, getting this one wrong in the permissive
    direction would be a real security hole, so the default is strict.
    """

    async def verify(
        self,
        receipt: Any,  # noqa: ARG002
        *,
        session_id: str,  # noqa: ARG002
        tool_name: str,  # noqa: ARG002
        arguments: Mapping[str, Any],  # noqa: ARG002
    ) -> bool:
        return False
