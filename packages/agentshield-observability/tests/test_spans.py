from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentshield_core.decision import Decision
from agentshield_observability import semconv as sc
from agentshield_observability.spans import (
    execute_tool_span,
    invoke_agent_span,
    record_decision,
    record_outcome,
)
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Tracer


def attrs(span: ReadableSpan) -> Mapping[str, Any]:
    """`ReadableSpan.attributes` is typed `Mapping[...] | None`; every
    assertion here only ever runs against a span that has already finished
    exporting, where attributes are always present.
    """
    assert span.attributes is not None
    return span.attributes


def test_invoke_agent_span_has_the_genai_operation_name_and_conversation_id(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    with invoke_agent_span(tracer, conversation_id="conv-1"):
        pass

    (span,) = exporter.get_finished_spans()
    assert span.name == "invoke_agent"
    assert attrs(span)[sc.GEN_AI_OPERATION_NAME] == "invoke_agent"
    assert attrs(span)[sc.GEN_AI_CONVERSATION_ID] == "conv-1"


def test_invoke_agent_span_optionally_carries_the_agent_name(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    with invoke_agent_span(tracer, conversation_id="conv-1", agent_name="triage-agent"):
        pass

    (span,) = exporter.get_finished_spans()
    assert attrs(span)[sc.GEN_AI_AGENT_NAME] == "triage-agent"


def test_execute_tool_span_has_tool_name_and_call_id_and_conversation_id(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    with execute_tool_span(
        tracer, conversation_id="conv-1", tool_name="send_email", tool_call_id="call-42"
    ):
        pass

    (span,) = exporter.get_finished_spans()
    assert span.name == "execute_tool send_email"
    assert attrs(span)[sc.GEN_AI_OPERATION_NAME] == "execute_tool"
    assert attrs(span)[sc.GEN_AI_TOOL_NAME] == "send_email"
    assert attrs(span)[sc.GEN_AI_TOOL_CALL_ID] == "call-42"
    assert attrs(span)[sc.GEN_AI_CONVERSATION_ID] == "conv-1"


def test_execute_tool_span_nests_under_a_current_invoke_agent_span(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    with (
        invoke_agent_span(tracer, conversation_id="conv-1") as agent_span,
        execute_tool_span(
            tracer, conversation_id="conv-1", tool_name="send_email", tool_call_id="call-1"
        ) as tool_span,
    ):
        pass

    spans = {s.name: s for s in exporter.get_finished_spans()}
    tool_recorded = spans["execute_tool send_email"]
    agent_recorded = spans["invoke_agent"]
    assert tool_recorded.parent is not None
    assert tool_recorded.parent.span_id == agent_recorded.context.span_id
    # sanity: the live span objects reported the same ids before export.
    assert tool_span.get_span_context().trace_id == agent_span.get_span_context().trace_id


def test_record_decision_sets_both_attributes_and_an_event(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    decision = Decision.deny("no policy permits this", stage="cedar_policy")

    with execute_tool_span(
        tracer, conversation_id="conv-1", tool_name="send_email", tool_call_id="call-1"
    ) as span:
        record_decision(span, decision)

    (recorded,) = exporter.get_finished_spans()
    assert attrs(recorded)[sc.AGENT_SHIELD_DECISION_KIND] == "DENY"
    assert attrs(recorded)[sc.AGENT_SHIELD_DECISION_STAGE] == "cedar_policy"
    assert attrs(recorded)[sc.AGENT_SHIELD_DECISION_REASON] == "no policy permits this"

    (event,) = recorded.events
    assert event.name == sc.EVENT_POLICY_DECISION
    assert event.attributes is not None
    assert event.attributes[sc.AGENT_SHIELD_DECISION_KIND] == "DENY"


def test_record_outcome_sets_enforcement_attributes(
    tracer: Tracer, exporter: InMemorySpanExporter
) -> None:
    with execute_tool_span(
        tracer, conversation_id="conv-1", tool_name="send_email", tool_call_id="call-1"
    ) as span:
        record_outcome(span, status_value="dispatched", enforced=True, enforcement_mode="enforce")

    (recorded,) = exporter.get_finished_spans()
    assert attrs(recorded)[sc.AGENT_SHIELD_OUTCOME_STATUS] == "dispatched"
    assert attrs(recorded)[sc.AGENT_SHIELD_ENFORCED] is True
    assert attrs(recorded)[sc.AGENT_SHIELD_ENFORCEMENT_MODE] == "enforce"
