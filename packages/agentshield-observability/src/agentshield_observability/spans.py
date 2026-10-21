"""OpenTelemetry span helpers following the GenAI semantic conventions
(`gen_ai.*`), so Agent Shield's spans drop into existing observability
tooling (any OTLP-compatible backend) rather than inventing a bespoke
trace format of our own.

`invoke_agent_span` is meant to be opened once per agent turn/conversation
by the caller (the gateway's HTTP handler, an SDK session, etc.);
`execute_tool_span`, opened per tool call, becomes its child automatically
through OpenTelemetry's own current-span context propagation as long as
it is opened while the `invoke_agent` span is still current -- this
module does no manual parent/child wiring of its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager

from agentshield_core.decision import Decision
from opentelemetry.trace import Span, SpanKind, Tracer

from agentshield_observability import semconv as sc


def invoke_agent_span(
    tracer: Tracer, *, conversation_id: str, agent_name: str | None = None
) -> AbstractContextManager[Span]:
    attributes: dict[str, str] = {
        sc.GEN_AI_OPERATION_NAME: sc.OPERATION_INVOKE_AGENT,
        sc.GEN_AI_CONVERSATION_ID: conversation_id,
    }
    if agent_name is not None:
        attributes[sc.GEN_AI_AGENT_NAME] = agent_name
    return tracer.start_as_current_span(
        sc.OPERATION_INVOKE_AGENT, kind=SpanKind.INTERNAL, attributes=attributes
    )


def execute_tool_span(
    tracer: Tracer, *, conversation_id: str, tool_name: str, tool_call_id: str
) -> AbstractContextManager[Span]:
    attributes: dict[str, str] = {
        sc.GEN_AI_OPERATION_NAME: sc.OPERATION_EXECUTE_TOOL,
        sc.GEN_AI_TOOL_NAME: tool_name,
        sc.GEN_AI_TOOL_CALL_ID: tool_call_id,
        sc.GEN_AI_CONVERSATION_ID: conversation_id,
    }
    return tracer.start_as_current_span(
        f"{sc.OPERATION_EXECUTE_TOOL} {tool_name}", kind=SpanKind.INTERNAL, attributes=attributes
    )


def decision_attributes(decision: Decision) -> dict[str, str]:
    return {
        sc.AGENT_SHIELD_DECISION_KIND: decision.kind.value,
        sc.AGENT_SHIELD_DECISION_STAGE: decision.stage,
        sc.AGENT_SHIELD_DECISION_REASON: decision.reason,
    }


def record_decision(span: Span, decision: Decision) -> None:
    """Attach `decision` to `span` as BOTH span attributes (so a backend's
    trace search/aggregation can filter and group by decision kind/stage)
    AND a span event (a precise, timestamped record of exactly when, in
    this span's lifetime, the decision was reached) -- the plan calls for
    both, and they serve different queries: attributes answer "show me
    every DENY on tool X", events answer "what happened, in order, during
    this one call".
    """
    attributes = decision_attributes(decision)
    span.set_attributes(attributes)
    span.add_event(sc.EVENT_POLICY_DECISION, attributes=attributes)


def record_outcome(span: Span, *, status_value: str, enforced: bool, enforcement_mode: str) -> None:
    span.set_attribute(sc.AGENT_SHIELD_OUTCOME_STATUS, status_value)
    span.set_attribute(sc.AGENT_SHIELD_ENFORCED, enforced)
    span.set_attribute(sc.AGENT_SHIELD_ENFORCEMENT_MODE, enforcement_mode)


def add_event(span: Span, name: str, attributes: Mapping[str, str] | None = None) -> None:
    span.add_event(name, attributes=dict(attributes) if attributes else None)
