from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
from agentshield_gateway.session import GatewaySession
from agentshield_observability import semconv as sc
from agentshield_observability.pipeline import EnforcementMode, InstrumentedDecisionPipeline
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Tracer

pytestmark = pytest.mark.asyncio


def attrs(span: ReadableSpan) -> Mapping[str, Any]:
    """`ReadableSpan.attributes` is typed `Mapping[...] | None`; every
    assertion here only ever runs against a span that has already finished
    exporting, where attributes are always present.
    """
    assert span.attributes is not None
    return span.attributes


#: Matches `conftest.py`'s `SEND_EMAIL_TOOL` exactly, so `authorized_session`'s
#: pin (established in that fixture) is satisfied by the `current_tool_schema`
#: passed on every request here -- redefined locally rather than imported,
#: matching this project's own test-file convention (see
#: `agentshield-gateway/tests/test_pipeline.py`).
SEND_EMAIL_TOOL: dict[str, object] = {
    "name": "send_email",
    "description": "Send an email on the user's behalf",
    "inputSchema": {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "body"],
    },
}


async def test_an_allowed_call_dispatches_and_is_fully_enforced_in_either_mode(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    instrumented = InstrumentedDecisionPipeline(pipeline=pipeline, tracer=tracer)
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)

    assert observed.outcome.status is OutcomeStatus.DISPATCHED
    assert observed.enforced is True
    assert observed.shadow_dispatched is False

    (span,) = exporter.get_finished_spans()
    assert span.name == "execute_tool send_email"
    assert attrs(span)[sc.AGENT_SHIELD_DECISION_KIND] == "ALLOW"
    assert attrs(span)[sc.AGENT_SHIELD_OUTCOME_STATUS] == "dispatched"
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCED] is True
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCEMENT_MODE] == "enforce"


async def test_a_denied_call_is_blocked_and_recorded_in_enforce_mode(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    instrumented = InstrumentedDecisionPipeline(
        pipeline=pipeline, tracer=tracer, mode=EnforcementMode.ENFORCE
    )
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)

    assert observed.outcome.status is OutcomeStatus.DENIED
    assert observed.enforced is True
    assert observed.shadow_dispatched is False
    assert observed.shadow_result is None

    (span,) = exporter.get_finished_spans()
    assert attrs(span)[sc.AGENT_SHIELD_DECISION_KIND] == "DENY"
    assert attrs(span)[sc.AGENT_SHIELD_OUTCOME_STATUS] == "denied"
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCED] is True
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCEMENT_MODE] == "enforce"
    event_names = [e.name for e in span.events]
    assert sc.EVENT_SHADOW_DISPATCH_ATTEMPTED not in event_names


async def test_a_denied_call_is_dispatched_anyway_in_shadow_mode(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    instrumented = InstrumentedDecisionPipeline(
        pipeline=pipeline, tracer=tracer, mode=EnforcementMode.SHADOW
    )
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)

    # The *real* decision was still a deny -- shadow mode never changes
    # what the pipeline decided, only whether the call was actually
    # allowed to proceed.
    assert observed.outcome.status is OutcomeStatus.DENIED
    assert observed.enforced is False
    assert observed.shadow_dispatched is True
    assert observed.shadow_result == {"sent_to": "mallory@example.com"}
    assert observed.shadow_error is None

    (span,) = exporter.get_finished_spans()
    assert attrs(span)[sc.AGENT_SHIELD_DECISION_KIND] == "DENY"
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCED] is False
    assert attrs(span)[sc.AGENT_SHIELD_ENFORCEMENT_MODE] == "shadow"
    event_names = [e.name for e in span.events]
    assert sc.EVENT_SHADOW_DISPATCH_ATTEMPTED in event_names
    assert sc.EVENT_SHADOW_DISPATCH_SUCCEEDED in event_names


async def test_an_allowed_call_in_shadow_mode_is_unaffected(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    """Shadow mode only changes behavior for calls the real pipeline would
    have denied -- an allowed call dispatches exactly once, the normal
    way, with no extra shadow dispatch attempted.
    """
    instrumented = InstrumentedDecisionPipeline(
        pipeline=pipeline, tracer=tracer, mode=EnforcementMode.SHADOW
    )
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)

    assert observed.outcome.status is OutcomeStatus.DISPATCHED
    assert observed.enforced is True
    assert observed.shadow_dispatched is False

    (span,) = exporter.get_finished_spans()
    event_names = [e.name for e in span.events]
    assert sc.EVENT_SHADOW_DISPATCH_ATTEMPTED not in event_names


async def test_a_shadow_dispatch_failure_is_recorded_rather_than_raised(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    class _FailingDispatcher:
        async def dispatch(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("downstream server unreachable")

    instrumented = InstrumentedDecisionPipeline(
        pipeline=pipeline, tracer=tracer, mode=EnforcementMode.SHADOW
    )
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(
        request, authorized_session, _FailingDispatcher()
    )

    assert observed.shadow_dispatched is True
    assert observed.shadow_result is None
    assert observed.shadow_error == "downstream server unreachable"

    (span,) = exporter.get_finished_spans()
    event_names = [e.name for e in span.events]
    assert sc.EVENT_SHADOW_DISPATCH_FAILED in event_names
    assert sc.EVENT_SHADOW_DISPATCH_SUCCEEDED not in event_names


async def test_a_dispatch_uncertain_outcome_is_treated_as_already_enforced(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    """An ALLOWed call whose *real* dispatch raised is already
    `DISPATCH_FAILED_UNCERTAIN`, not `DENIED` -- shadow mode must not
    additionally re-dispatch an already-attempted call.
    """

    class _FailingDispatcher:
        async def dispatch(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
            raise RuntimeError("boom")

    instrumented = InstrumentedDecisionPipeline(
        pipeline=pipeline, tracer=tracer, mode=EnforcementMode.SHADOW
    )
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    observed = await instrumented.evaluate_and_dispatch(
        request, authorized_session, _FailingDispatcher()
    )

    assert observed.outcome.status is OutcomeStatus.DISPATCH_FAILED_UNCERTAIN
    assert observed.enforced is True
    assert observed.shadow_dispatched is False


async def test_each_call_gets_a_fresh_tool_call_id_when_not_provided(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    instrumented = InstrumentedDecisionPipeline(pipeline=pipeline, tracer=tracer)
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)
    await instrumented.evaluate_and_dispatch(request, authorized_session, dispatcher)

    first, second = exporter.get_finished_spans()
    assert attrs(first)[sc.GEN_AI_TOOL_CALL_ID] != attrs(second)[sc.GEN_AI_TOOL_CALL_ID]


async def test_an_explicit_tool_call_id_and_conversation_id_are_honored(
    pipeline: DecisionPipeline,
    authorized_session: GatewaySession,
    dispatcher: ToolDispatcher,
    tracer: Tracer,
    exporter: InMemorySpanExporter,
) -> None:
    instrumented = InstrumentedDecisionPipeline(pipeline=pipeline, tracer=tracer)
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com", "body": "hi"},
        raw_context={"principal": "s1"},
        current_tool_schema=SEND_EMAIL_TOOL,
    )

    await instrumented.evaluate_and_dispatch(
        request,
        authorized_session,
        dispatcher,
        conversation_id="conv-xyz",
        tool_call_id="call-xyz",
    )

    (span,) = exporter.get_finished_spans()
    assert attrs(span)[sc.GEN_AI_CONVERSATION_ID] == "conv-xyz"
    assert attrs(span)[sc.GEN_AI_TOOL_CALL_ID] == "call-xyz"
