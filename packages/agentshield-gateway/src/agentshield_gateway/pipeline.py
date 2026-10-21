"""The ordered, fail-closed decision pipeline. This module is the gateway's
actual Policy Enforcement Point: everything else in this package (FastAPI
routes, the mcp v2 middleware, the dispatchers) is plumbing around this one
class.

The pipeline runs in a fixed order and stops at the first DENY, so no later
stage can re-permit an earlier refusal:

1. Resolve principal identity. Unresolvable identity denies.
2. Check the capability granted for this (session, tool): it must exist,
   be unexpired, be minted under the current revocation epoch, and its
   caveats must all be satisfied by these arguments. Any failure denies.
3. Verify the pinned tool-schema digest against what the server currently
   advertises. A mismatch is a rug pull and denies.
4. Evaluate the Cedar policy set with the call's typed arguments as action
   context. Cedar's own answer is binary (allow/deny); immediately
   afterwards, consult the pluggable `ApprovalPolicy` for consequence-based
   tiering, since Cedar alone cannot express "allowed, but only with human
   sign-off" -- this is the one place this implementation extends the
   plan's eight stages, and it is folded into stage 4 rather than given its
   own number because it answers the same question stage 4 asks (is this
   call, with these arguments, authorized) with a richer answer than a
   binary allow/deny.
5. Evaluate the information-flow rule: the session's accumulated label,
   joined with whatever label the call's own arguments carry, must satisfy
   the tool's declared ceiling.
6. Evaluate the lethal-trifecta invariant: this call must not be the one
   that completes all three legs at once.
7. If any stage above returned REQUIRE_APPROVAL rather than ALLOW, verify
   the attached receipt. No valid receipt denies.
8. Dispatch, then write the outcome -- including "uncertain" if dispatch
   itself raised -- to the ledger. Every reachable branch of this pipeline
   writes to the ledger exactly once, including every denial: an audit log
   that only remembers successes is not an audit log the plan requires.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from agentshield_core.decision import Decision, most_severe
from agentshield_core.labels import Label
from agentshield_core.provenance import ProvenanceNode
from agentshield_core.quotas import QuotaStore
from agentshield_ledger.ledger import Ledger
from agentshield_ledger.verify.hashchain import ChainedEntry
from agentshield_policy.pdp import PolicyDecisionPoint

from agentshield_gateway.boundaries import (
    ApprovalPolicy,
    EpochSource,
    KeyPrincipalResolver,
    NeverRequiresApproval,
    PrincipalResolver,
    ReceiptVerifier,
    RejectAllReceiptVerifier,
    ZeroEpochSource,
)
from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.egress import EgressPolicy
from agentshield_gateway.registry import ToolRegistry
from agentshield_gateway.session import GatewaySession


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    raw_context: Mapping[str, Any] = field(default_factory=dict)
    current_tool_schema: dict[str, Any] | None = None
    input_label: Label = field(default_factory=Label.bottom)
    receipt: Any | None = None
    # Optional: the full provenance DAG node for this call's argument(s), if
    # the caller (typically `agentshield-sdk`'s per-value tracking) has one.
    # Purely additive and never consulted for the label-ceiling decision
    # itself (`input_label` alone still drives that) -- it only enriches
    # *why* a denial happened at the information-flow stage with an actual
    # provenance chain, for the console's audit explorer (see
    # `agentshield_core.provenance.ProvenanceNode.explain`).
    input_provenance: ProvenanceNode | None = None


class OutcomeStatus(StrEnum):
    DENIED = "denied"
    DISPATCHED = "dispatched"
    DISPATCH_FAILED_UNCERTAIN = "dispatch_failed_uncertain"


@dataclass(frozen=True, slots=True)
class GatewayOutcome:
    decision: Decision
    status: OutcomeStatus
    result: dict[str, Any] | None = None
    ledger_entry: ChainedEntry | None = None


class DecisionPipeline:
    def __init__(
        self,
        *,
        policy_decision_point: PolicyDecisionPoint,
        ledger: Ledger,
        tool_registry: ToolRegistry | None = None,
        principal_resolver: PrincipalResolver | None = None,
        epoch_source: EpochSource | None = None,
        approval_policy: ApprovalPolicy | None = None,
        receipt_verifier: ReceiptVerifier | None = None,
        egress_policy: EgressPolicy | None = None,
        quota_store: QuotaStore | None = None,
    ) -> None:
        self._pdp = policy_decision_point
        self._ledger = ledger
        self._tool_registry = tool_registry or ToolRegistry()
        self._principal_resolver = principal_resolver or KeyPrincipalResolver()
        self._epoch_source = epoch_source or ZeroEpochSource()
        self._approval_policy = approval_policy or NeverRequiresApproval()
        self._receipt_verifier = receipt_verifier or RejectAllReceiptVerifier()
        self._egress_policy = egress_policy or EgressPolicy()
        self._quota_store = quota_store or QuotaStore()

    @property
    def tool_registry(self) -> ToolRegistry:
        return self._tool_registry

    async def evaluate_and_dispatch(
        self,
        request: ToolCallRequest,
        session: GatewaySession,
        dispatcher: ToolDispatcher,
    ) -> GatewayOutcome:
        decisions: list[Decision] = []

        # --- Step 1: principal identity -------------------------------
        principal = self._principal_resolver.resolve(request.raw_context)
        if principal is None:
            return self._deny(
                request,
                Decision.deny("principal identity could not be resolved", stage="principal"),
            )
        session.principal = principal

        # --- Step 2: capability (epoch + expiry + caveats) -------------
        capability = session.capabilities.get(request.tool_name)
        current_epoch = await self._epoch_source.current_epoch(request.session_id)
        if capability is None or not capability.permits(
            request.arguments, current_epoch=current_epoch
        ):
            return self._deny(
                request,
                Decision.deny(
                    f"no valid, unexpired, in-epoch capability authorizes tool "
                    f"{request.tool_name!r} with these arguments",
                    stage="capability",
                ),
            )
        quota_reason = self._quota_store.check(capability.capability_id, request.arguments)
        if quota_reason is not None:
            return self._deny(request, Decision.deny(quota_reason, stage="quota"))

        # --- Step 3: tool-schema pinning / rug-pull detection -----------
        if not session.pinned_tools.check(request.tool_name, request.current_tool_schema):
            return self._deny(
                request,
                Decision.deny(
                    f"tool schema digest mismatch for {request.tool_name!r} -- "
                    "possible rug pull, or schema could not be verified",
                    stage="schema_pin",
                ),
            )

        # --- Step 4: Cedar policy, then approval tiering ----------------
        try:
            cedar_decision = self._pdp.authorize(
                session_id=request.session_id,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
        except Exception as exc:  # noqa: BLE001 - fail-closed: a raising PDP is a deny
            return self._deny(
                request,
                Decision.deny(f"policy engine error, failing closed: {exc}", stage="cedar_policy"),
            )
        decisions.append(cedar_decision)
        if cedar_decision.is_denied:
            return self._deny(request, cedar_decision)
        try:
            egress_decision = self._egress_policy.inspect(request.tool_name, request.arguments)
        except Exception as exc:  # noqa: BLE001 - fail-closed
            return self._deny(
                request,
                Decision.deny(f"egress check error, failing closed: {exc}", stage="egress"),
            )
        if egress_decision.is_denied:
            return self._deny(request, egress_decision)
        try:
            needs_approval = self._approval_policy.requires_approval(
                request.tool_name, request.arguments
            )
        except Exception as exc:  # noqa: BLE001 - fail-closed
            return self._deny(
                request,
                Decision.deny(
                    f"approval-tiering error, failing closed: {exc}", stage="approval_tiering"
                ),
            )
        if needs_approval:
            decisions.append(
                Decision.require_approval(
                    f"tool {request.tool_name!r} is consequence-tiered and requires "
                    "a verified human-approval receipt",
                    stage="approval_tiering",
                )
            )

        # --- Step 5: information-flow ceiling ---------------------------
        profile = self._tool_registry.get(request.tool_name)
        if profile is None:
            return self._deny(
                request,
                Decision.deny(
                    f"no registered security profile for tool {request.tool_name!r}",
                    stage="information_flow",
                ),
            )
        effective_label = session.current_label.join(request.input_label)
        if not effective_label.satisfies_ceiling(profile.ceiling):
            reason = (
                f"session's accumulated label ({effective_label.integrity.name}/"
                f"{effective_label.confidentiality.name}) exceeds tool "
                f"{request.tool_name!r}'s declared ceiling "
                f"({profile.ceiling.integrity.name}/{profile.ceiling.confidentiality.name})"
            )
            return self._deny(
                request,
                Decision.deny(reason, stage="information_flow"),
                provenance_path=(
                    request.input_provenance.explain()
                    if request.input_provenance is not None
                    else None
                ),
            )

        # --- Step 6: lethal-trifecta invariant --------------------------
        if profile.trifecta_leg is not None and session.trifecta.would_complete_trifecta(
            profile.trifecta_leg
        ):
            return self._deny(
                request,
                Decision.deny(
                    f"calling {request.tool_name!r} would complete the lethal trifecta "
                    f"({session.trifecta.describe()}, acquiring {profile.trifecta_leg.value})",
                    stage="trifecta",
                ),
            )

        overall = most_severe(tuple(decisions))

        # --- Step 7: approval receipt (only if some stage required it) --
        if overall.needs_approval:
            receipt_ok = request.receipt is not None and await self._receipt_verifier.verify(
                request.receipt,
                session_id=request.session_id,
                tool_name=request.tool_name,
                arguments=request.arguments,
            )
            if not receipt_ok:
                return self._deny(
                    request,
                    Decision.deny(
                        "approval required but no valid, unused, unexpired receipt "
                        "was presented for this exact call",
                        stage="receipt",
                    ),
                )
            # The receipt satisfies the approval requirement: this *replaces*
            # the REQUIRE_APPROVAL verdict with ALLOW, rather than folding an
            # ALLOW into the existing decision list -- `most_severe` would
            # just pick the REQUIRE_APPROVAL again, since it outranks ALLOW
            # regardless of what else is added alongside it.
            overall = Decision.allow(
                "valid approval receipt verified for a call that required one",
                stage="receipt",
            )

        # The call is fully authorized. Commit session state -- the risk
        # of holding this label / this trifecta leg is incurred the moment
        # the call is permitted to proceed, independent of whether dispatch
        # itself later succeeds or fails.
        session.current_label = effective_label
        if profile.trifecta_leg is not None:
            session.trifecta = session.trifecta.with_leg_acquired(profile.trifecta_leg)
        self._quota_store.consume(capability.capability_id, request.arguments)

        self._ledger.append(
            "decision",
            {
                "session_id": request.session_id,
                "tool": request.tool_name,
                "decision": overall.kind.value,
                "stage": overall.stage,
                "reason": overall.reason,
            },
        )

        # --- Step 8: dispatch, then record the outcome ------------------
        try:
            result = await dispatcher.dispatch(request.tool_name, request.arguments)
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any dispatch
            # failure, of any kind, becomes an "uncertain" ledger entry, never a
            # silently-dropped one.
            entry = self._ledger.append(
                "tool_outcome",
                {
                    "session_id": request.session_id,
                    "tool": request.tool_name,
                    "status": "uncertain",
                    "error": str(exc),
                },
            )
            return GatewayOutcome(
                decision=overall,
                status=OutcomeStatus.DISPATCH_FAILED_UNCERTAIN,
                result=None,
                ledger_entry=entry,
            )

        entry = self._ledger.append(
            "tool_outcome",
            {
                "session_id": request.session_id,
                "tool": request.tool_name,
                "status": "ok",
                "result": result,
            },
        )
        return GatewayOutcome(
            decision=overall, status=OutcomeStatus.DISPATCHED, result=result, ledger_entry=entry
        )

    def _deny(
        self,
        request: ToolCallRequest,
        decision: Decision,
        *,
        provenance_path: str | None = None,
    ) -> GatewayOutcome:
        payload: dict[str, Any] = {
            "session_id": request.session_id,
            "tool": request.tool_name,
            "decision": decision.kind.value,
            "stage": decision.stage,
            "reason": decision.reason,
        }
        # Only ever attached when the caller supplied `input_provenance` and
        # the denial happened at the information-flow stage -- this is a
        # strict audit-trail enrichment, never consulted by any decision
        # logic, so a session that never supplies provenance behaves
        # identically to before this field existed.
        if provenance_path is not None:
            payload["provenance_path"] = provenance_path
        entry = self._ledger.append("decision", payload)
        return GatewayOutcome(
            decision=decision, status=OutcomeStatus.DENIED, result=None, ledger_entry=entry
        )
