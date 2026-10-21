from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from agentshield_core.capabilities import Capability, arg_equals
from agentshield_core.decision import DecisionKind
from agentshield_core.labels import Confidentiality, Integrity, Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
from agentshield_gateway.session import GatewaySession

pytestmark = pytest.mark.asyncio

# Must stay byte-for-byte identical to the fixtures of the same name in
# conftest.py: `authorized_session` pins its digests from those, and a
# divergent copy here would make step 3 (schema pinning) spuriously deny
# every call as a false "rug pull".
SEND_EMAIL_TOOL = {
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

TRANSFER_FUNDS_TOOL = {
    "name": "transfer_funds",
    "description": "Transfer money between accounts",
    "inputSchema": {
        "type": "object",
        "properties": {
            "to_account": {"type": "string"},
            "amount_usd": {"type": "integer"},
        },
        "required": ["to_account", "amount_usd"],
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
    d = InMemoryToolDispatcher()
    d.register("send_email", lambda args: _ok_result(args))
    return d


async def _ok_result(args: dict[str, Any]) -> dict[str, Any]:
    return {"sent": True, "to": args.get("to")}


async def test_fully_authorized_call_dispatches_and_is_allowed(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert outcome.status is OutcomeStatus.DISPATCHED
    assert outcome.result == {"sent": True, "to": "alice@example.com"}


async def test_step1_unresolvable_principal_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(raw_context={}), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "principal"


async def test_step2_missing_capability_denies(
    pipeline: DecisionPipeline, sample_tools: list[dict[str, object]]
) -> None:
    from agentshield_gateway.schema_pinning import PinnedToolSet

    session = GatewaySession(session_id="s1")
    session.pinned_tools = PinnedToolSet.pin(sample_tools)
    # Deliberately no capability granted.
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), session, dispatcher)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "capability"


async def test_step2_expired_capability_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    authorized_session.grant_capability(
        Capability.mint(session_id="s1", tool_name="send_email", epoch=0, ttl_seconds=-1.0)
    )
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "capability"


async def test_step2_stale_epoch_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    stale = Capability.mint(session_id="s1", tool_name="send_email", epoch=1, ttl_seconds=300.0)
    authorized_session.grant_capability(stale)  # current epoch source always returns 0
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "capability"


async def test_step2_caveat_violation_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    narrowed = Capability.mint(
        session_id="s1",
        tool_name="send_email",
        epoch=0,
        ttl_seconds=300.0,
        caveats_=(arg_equals("to", "bob@example.com"),),
    )
    authorized_session.grant_capability(narrowed)
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "capability"


async def test_step3_schema_rug_pull_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    tampered_schema = {**SEND_EMAIL_TOOL, "description": "Send an email to anyone, anywhere"}
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(current_tool_schema=tampered_schema), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "schema_pin"


async def test_step3_missing_current_schema_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(current_tool_schema=None), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "schema_pin"


async def test_step4_cedar_denies_outside_policy(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(arguments={"to": "mallory@example.com", "body": "hi"}),
        authorized_session,
        dispatcher,
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "cedar_policy"


async def test_step4_approval_tiering_requires_a_receipt(
    policy_decision_point: Any, ledger: Any, tool_registry: Any, authorized_session: GatewaySession
) -> None:
    class AlwaysTier:
        def requires_approval(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
            return tool_name == "send_email"

    class AcceptAnyReceipt:
        async def verify(self, receipt: Any, **_: Any) -> bool:
            return bool(receipt == "valid-receipt")

    tiered_pipeline = DecisionPipeline(
        policy_decision_point=policy_decision_point,
        ledger=ledger,
        tool_registry=tool_registry,
        approval_policy=AlwaysTier(),
        receipt_verifier=AcceptAnyReceipt(),
    )
    dispatcher = await _dispatcher_ok()

    denied = await tiered_pipeline.evaluate_and_dispatch(
        _request(receipt=None), authorized_session, dispatcher
    )
    assert denied.decision.kind is DecisionKind.DENY
    assert denied.decision.stage == "receipt"

    allowed = await tiered_pipeline.evaluate_and_dispatch(
        _request(receipt="valid-receipt"), authorized_session, dispatcher
    )
    assert allowed.status is OutcomeStatus.DISPATCHED
    assert allowed.decision.kind is DecisionKind.ALLOW


async def test_step5_unregistered_tool_denies(
    policy_decision_point: Any, ledger: Any, authorized_session: GatewaySession
) -> None:
    from agentshield_gateway.registry import ToolRegistry

    empty_registry = ToolRegistry()  # send_email never registered
    pipeline_no_registry = DecisionPipeline(
        policy_decision_point=policy_decision_point, ledger=ledger, tool_registry=empty_registry
    )
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline_no_registry.evaluate_and_dispatch(
        _request(), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "information_flow"


async def test_step5_label_ceiling_exceeded_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    secret_input = Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.SECRET)
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(input_label=secret_input), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "information_flow"


async def test_step5_label_ceiling_exceeded_records_provenance_path_when_supplied(
    pipeline: DecisionPipeline, authorized_session: GatewaySession, ledger: Any
) -> None:
    """When the caller attaches `input_provenance`, an information-flow
    denial's ledger entry carries a human-readable provenance chain (see
    `agentshield_core.provenance.ProvenanceNode.explain`) -- the raw
    material for the console's audit explorer. A call that supplies no
    provenance (every other test in this file) must be completely
    unaffected: no `provenance_path` key appears in its ledger payload at
    all, not even as `None`.
    """
    from agentshield_core.provenance import ProvenanceNode

    secret_input = Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.SECRET)
    origin = ProvenanceNode.origin("tool:read_email#msg_42", secret_input)
    dispatcher = await _dispatcher_ok()

    outcome = await pipeline.evaluate_and_dispatch(
        _request(input_label=secret_input, input_provenance=origin),
        authorized_session,
        dispatcher,
    )

    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "information_flow"
    assert outcome.ledger_entry is not None
    payload = outcome.ledger_entry.entry["payload"]
    assert "msg_42" in payload["provenance_path"]
    assert len(ledger.entries) == 1


async def test_step5_label_within_ceiling_allows(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    private_input = Label.private()  # send_email's ceiling is exactly Label.private()
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(
        _request(input_label=private_input), authorized_session, dispatcher
    )
    assert outcome.decision.kind is DecisionKind.ALLOW
    assert authorized_session.current_label == private_input


async def test_step6_trifecta_completion_denies(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    authorized_session.trifecta = authorized_session.trifecta.with_leg_acquired(
        TrifectaLeg.UNTRUSTED_INPUT
    ).with_leg_acquired(TrifectaLeg.PRIVATE_DATA)
    dispatcher = await _dispatcher_ok()
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.decision.kind is DecisionKind.DENY
    assert outcome.decision.stage == "trifecta"


async def test_step6_non_trifecta_tool_is_unaffected(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    authorized_session.trifecta = authorized_session.trifecta.with_leg_acquired(
        TrifectaLeg.UNTRUSTED_INPUT
    ).with_leg_acquired(TrifectaLeg.PRIVATE_DATA)
    dispatcher = InMemoryToolDispatcher()
    dispatcher.register("transfer_funds", lambda args: _ok_result({"to": args.get("to_account")}))
    outcome = await pipeline.evaluate_and_dispatch(
        _request(
            tool_name="transfer_funds",
            arguments={"to_account": "acct-1", "amount_usd": 10},
            current_tool_schema=TRANSFER_FUNDS_TOOL,
        ),
        authorized_session,
        dispatcher,
    )
    assert outcome.decision.kind is DecisionKind.ALLOW


async def test_step8_dispatch_failure_is_recorded_as_uncertain(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    dispatcher = InMemoryToolDispatcher()

    async def _boom(args: dict[str, Any]) -> dict[str, Any]:
        raise ConnectionError("downstream unreachable")

    dispatcher.register("send_email", _boom)
    outcome = await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert outcome.status is OutcomeStatus.DISPATCH_FAILED_UNCERTAIN
    assert outcome.decision.kind is DecisionKind.ALLOW  # authorization itself succeeded
    assert outcome.ledger_entry is not None
    assert outcome.ledger_entry.entry["payload"]["status"] == "uncertain"


async def test_every_denial_is_still_written_to_the_ledger(
    pipeline: DecisionPipeline, authorized_session: GatewaySession, ledger: Any
) -> None:
    dispatcher = await _dispatcher_ok()
    await pipeline.evaluate_and_dispatch(_request(raw_context={}), authorized_session, dispatcher)
    assert len(ledger.entries) == 1
    assert ledger.entries[0].entry["payload"]["decision"] == "DENY"
    assert ledger.entries[0].entry["payload"]["stage"] == "principal"
    assert "provenance_path" not in ledger.entries[0].entry["payload"]


async def test_allowed_call_writes_a_decision_entry_and_a_result_entry(
    pipeline: DecisionPipeline, authorized_session: GatewaySession, ledger: Any
) -> None:
    dispatcher = await _dispatcher_ok()
    await pipeline.evaluate_and_dispatch(_request(), authorized_session, dispatcher)
    assert len(ledger.entries) == 2
    assert ledger.entries[0].entry["event_type"] == "decision"
    assert ledger.entries[1].entry["event_type"] == "tool_outcome"
    assert ledger.entries[1].entry["payload"]["status"] == "ok"


async def test_stops_at_first_denial_and_does_not_dispatch(
    pipeline: DecisionPipeline, authorized_session: GatewaySession
) -> None:
    """A capability-stage denial (step 2) must prevent dispatch, even though
    nothing about steps 4-8 was ever evaluated.
    """
    session = GatewaySession(session_id="s1")
    session.pinned_tools = authorized_session.pinned_tools  # pinned, but no capability granted

    dispatch_was_called = False

    class _Spy:
        async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            nonlocal dispatch_was_called
            dispatch_was_called = True
            return {}

    outcome = await pipeline.evaluate_and_dispatch(_request(), session, _Spy())
    assert outcome.decision.kind is DecisionKind.DENY
    assert dispatch_was_called is False
