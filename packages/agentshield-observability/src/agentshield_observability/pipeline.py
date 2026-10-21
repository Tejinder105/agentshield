"""Wraps `agentshield_gateway.pipeline.DecisionPipeline` with OpenTelemetry
spans (GenAI semantic conventions, see `agentshield_observability.spans`)
and an optional shadow/log-only enforcement mode.

Shadow mode runs the exact same pipeline -- every stage (capability,
schema pinning, Cedar, information flow, trifecta, approval receipt)
still evaluates for real, and the resulting `Decision` is still recorded
in full, via spans and (through the wrapped pipeline's own `Ledger.append`
calls, never bypassed here) the ledger. The only difference is what
happens next: in `ENFORCE` mode a DENY stops the call exactly as
`DecisionPipeline` already does; in `SHADOW` mode this module additionally
dispatches the call anyway, so a team can see what *would* have been
blocked once enforcement is turned on, without actually blocking
production traffic in the meantime. Session state (the accumulated label,
the trifecta, capability consumption) is never mutated by a denied call in
the wrapped pipeline either way -- `DecisionPipeline.evaluate_and_dispatch`
only commits those on a real ALLOW -- so there is nothing for shadow mode
to additionally guard against or undo.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import GatewayOutcome, OutcomeStatus, ToolCallRequest
from agentshield_gateway.session import GatewaySession
from opentelemetry.trace import Tracer

from agentshield_observability import semconv as sc
from agentshield_observability.spans import add_event, execute_tool_span, record_decision


class EnforcementMode(StrEnum):
    ENFORCE = "enforce"
    SHADOW = "shadow"


class Pipeline(Protocol):
    """The one method of `DecisionPipeline` this module depends on,
    expressed structurally so a test double never has to subclass the
    real gateway pipeline.
    """

    async def evaluate_and_dispatch(
        self, request: ToolCallRequest, session: GatewaySession, dispatcher: ToolDispatcher
    ) -> GatewayOutcome: ...


@dataclass(frozen=True, slots=True)
class ObservedOutcome:
    """What actually happened for one tool call, instrumentation included.

    `outcome` is always the *real* pipeline's answer -- what it decided,
    and what it actually dispatched (if anything). `enforced` is `False`
    only in the one case shadow mode changes anything: the real pipeline
    denied the call, but this call was additionally dispatched anyway so
    its effect could be observed; `shadow_result`/`shadow_error` hold
    whichever of those the extra dispatch produced.
    """

    outcome: GatewayOutcome
    enforced: bool
    shadow_dispatched: bool
    shadow_result: dict[str, Any] | None = None
    shadow_error: str | None = None


@dataclass(slots=True)
class InstrumentedDecisionPipeline:
    pipeline: Pipeline
    tracer: Tracer
    mode: EnforcementMode = EnforcementMode.ENFORCE

    async def evaluate_and_dispatch(
        self,
        request: ToolCallRequest,
        session: GatewaySession,
        dispatcher: ToolDispatcher,
        *,
        conversation_id: str | None = None,
        tool_call_id: str | None = None,
    ) -> ObservedOutcome:
        conversation_id = conversation_id or request.session_id
        tool_call_id = tool_call_id or str(uuid.uuid4())

        with execute_tool_span(
            self.tracer,
            conversation_id=conversation_id,
            tool_name=request.tool_name,
            tool_call_id=tool_call_id,
        ) as span:
            outcome = await self.pipeline.evaluate_and_dispatch(request, session, dispatcher)
            record_decision(span, outcome.decision)

            if outcome.status is not OutcomeStatus.DENIED or self.mode is EnforcementMode.ENFORCE:
                span.set_attribute(sc.AGENT_SHIELD_OUTCOME_STATUS, outcome.status.value)
                span.set_attribute(sc.AGENT_SHIELD_ENFORCED, True)
                span.set_attribute(sc.AGENT_SHIELD_ENFORCEMENT_MODE, self.mode.value)
                return ObservedOutcome(outcome=outcome, enforced=True, shadow_dispatched=False)

            # SHADOW mode and the real pipeline denied: dispatch anyway.
            span.set_attribute(sc.AGENT_SHIELD_OUTCOME_STATUS, outcome.status.value)
            span.set_attribute(sc.AGENT_SHIELD_ENFORCED, False)
            span.set_attribute(sc.AGENT_SHIELD_ENFORCEMENT_MODE, self.mode.value)
            add_event(span, sc.EVENT_SHADOW_DISPATCH_ATTEMPTED)
            try:
                shadow_result = await dispatcher.dispatch(request.tool_name, request.arguments)
            except Exception as exc:  # noqa: BLE001 - mirrors DecisionPipeline's own
                # "any dispatch failure becomes an observed-but-uncertain outcome,
                # never a silently-dropped one" rule from its step 8.
                add_event(span, sc.EVENT_SHADOW_DISPATCH_FAILED, {"error": str(exc)})
                return ObservedOutcome(
                    outcome=outcome,
                    enforced=False,
                    shadow_dispatched=True,
                    shadow_error=str(exc),
                )

            add_event(span, sc.EVENT_SHADOW_DISPATCH_SUCCEEDED)
            return ObservedOutcome(
                outcome=outcome,
                enforced=False,
                shadow_dispatched=True,
                shadow_result=shadow_result,
            )
