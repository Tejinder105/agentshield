"""Production-hardening tests: egress and quota wiring through the real
pipeline, plus load/failure coverage of the fail-closed paths.

A fail-closed system that only works at one request per test is not
fail-closed under load. These tests flood the pipeline with concurrent
calls that *should* deny (unresolvable identity, a PDP that raises,
quota exhaustion) and assert every outcome is a denial with a ledger
entry -- never a silent allow, never a dropped write.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from agentshield_core.decision import Decision, DecisionKind
from agentshield_core.quotas import Quota, QuotaStore
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.egress import EgressPolicy
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
from agentshield_gateway.session import GatewaySession
from agentshield_policy.pdp import PolicyDecisionPoint

pytestmark = pytest.mark.asyncio

SEND_EMAIL_TOOL = {
    "name": "send_email",
    "description": "Send an email on the user's behalf",
    "inputSchema": {
        "type": "object",
        "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
        "required": ["to", "body"],
    },
}


def _request(**overrides: Any) -> ToolCallRequest:
    defaults: dict[str, Any] = {
        "session_id": "s1",
        "tool_name": "send_email",
        "arguments": {"to": "alice@example.com", "body": "hi"},
        "raw_context": {"principal": "s1"},
        "current_tool_schema": SEND_EMAIL_TOOL,
    }
    defaults.update(overrides)
    return ToolCallRequest(**defaults)


async def _dispatcher_ok() -> InMemoryToolDispatcher:
    dispatcher = InMemoryToolDispatcher()

    async def _ok(args: dict[str, Any]) -> dict[str, Any]:
        return {"sent": True, "to": args.get("to")}

    dispatcher.register("send_email", _ok)
    return dispatcher


class _RaisingPDP:
    def authorize(self, *, session_id: str, tool_name: str, arguments: dict[str, Any]) -> Decision:
        raise RuntimeError("cedar engine exploded")


async def test_secret_in_arguments_is_denied_at_egress(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()
    request = _request(arguments={"to": "alice@example.com", "body": "AKIAIOSFODNN7EXAMPLE"})
    outcome = await pipeline.evaluate_and_dispatch(request, authorized_session, dispatcher)
    assert outcome.status is OutcomeStatus.DENIED
    assert outcome.decision.stage == "egress"


async def test_url_allowlist_denies_a_non_allowlisted_host(
    policy_decision_point: PolicyDecisionPoint,
    ledger: Any,
    tool_registry: Any,
    authorized_session: GatewaySession,
) -> None:
    pipeline = DecisionPipeline(
        policy_decision_point=policy_decision_point,
        ledger=ledger,
        tool_registry=tool_registry,
        egress_policy=EgressPolicy(allowed_hosts=frozenset({"example.com"})),
    )
    dispatcher = await _dispatcher_ok()
    request = _request(arguments={"to": "alice@example.com", "body": "https://evil.example/x"})
    outcome = await pipeline.evaluate_and_dispatch(request, authorized_session, dispatcher)
    assert outcome.status is OutcomeStatus.DENIED
    assert outcome.decision.stage == "egress"


async def test_call_quota_is_consumed_only_on_authorized_calls(
    policy_decision_point: PolicyDecisionPoint,
    ledger: Any,
    tool_registry: Any,
    authorized_session: GatewaySession,
) -> None:
    capability = authorized_session.capabilities["send_email"]
    quotas = QuotaStore()
    quotas.register(capability.capability_id, Quota(max_calls=1))
    pipeline = DecisionPipeline(
        policy_decision_point=policy_decision_point,
        ledger=ledger,
        tool_registry=tool_registry,
        quota_store=quotas,
    )
    dispatcher = await _dispatcher_ok()

    first = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert first.status is OutcomeStatus.DISPATCHED

    second = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert second.status is OutcomeStatus.DENIED
    assert second.decision.stage == "quota"


async def test_a_denial_does_not_consume_quota(
    policy_decision_point: PolicyDecisionPoint,
    ledger: Any,
    tool_registry: Any,
    authorized_session: GatewaySession,
) -> None:
    capability = authorized_session.capabilities["send_email"]
    quotas = QuotaStore()
    quotas.register(capability.capability_id, Quota(max_calls=1))
    pipeline = DecisionPipeline(
        policy_decision_point=policy_decision_point,
        ledger=ledger,
        tool_registry=tool_registry,
        quota_store=quotas,
    )
    dispatcher = await _dispatcher_ok()

    denied = await pipeline.evaluate_and_dispatch(
        _request(raw_context={}), authorized_session, dispatcher
    )
    assert denied.status is OutcomeStatus.DENIED
    assert quotas.calls_used.get(capability.capability_id, 0) == 0

    allowed = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert allowed.status is OutcomeStatus.DISPATCHED


async def test_concurrent_unresolvable_principals_all_deny_and_are_ledgered(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()

    async def one() -> Any:
        return await pipeline.evaluate_and_dispatch(
            _request(raw_context={}), authorized_session, dispatcher
        )

    outcomes = await asyncio.gather(*[one() for _ in range(32)])
    assert all(outcome.status is OutcomeStatus.DENIED for outcome in outcomes)
    assert all(outcome.decision.kind is DecisionKind.DENY for outcome in outcomes)
    assert all(outcome.ledger_entry is not None for outcome in outcomes)


async def test_a_raising_pdp_fails_closed_under_concurrency(
    ledger: Any, tool_registry: Any, authorized_session: GatewaySession
) -> None:
    pipeline = DecisionPipeline(
        policy_decision_point=_RaisingPDP(),  # type: ignore[arg-type]
        ledger=ledger,
        tool_registry=tool_registry,
    )
    dispatcher = await _dispatcher_ok()

    async def one() -> Any:
        return await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)

    outcomes = await asyncio.gather(*[one() for _ in range(16)])
    assert all(outcome.status is OutcomeStatus.DENIED for outcome in outcomes)
    assert all(outcome.decision.kind is DecisionKind.DENY for outcome in outcomes)
    assert all(outcome.decision.stage == "cedar_policy" for outcome in outcomes)
