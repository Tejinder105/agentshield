from __future__ import annotations

import pytest
from agentshield_approvals.nonce_store import InMemoryNonceStore
from agentshield_approvals.queue import ApprovalStatus, InMemoryPendingApprovalQueue
from agentshield_approvals.service import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    ApprovalService,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio


def _service() -> ApprovalService:
    key = Ed25519PrivateKey.generate()
    return ApprovalService(
        signing_key=key,
        public_key_hex=key.public_key().public_bytes_raw().hex(),
        queue=InMemoryPendingApprovalQueue(),
        nonce_store=InMemoryNonceStore(),
        receipt_ttl_seconds=120.0,
    )


async def test_full_request_approve_verify_cycle() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="send_email", arguments={"to": "alice"}, resource_version=1
    )
    receipt = await service.approve(pending.request_id, nonce="n1")

    ok = await service.verify(
        receipt, session_id="s1", tool_name="send_email", arguments={"to": "alice"}
    )
    assert ok is True


async def test_receipt_cannot_be_redeemed_twice() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="send_email", arguments={"to": "alice"}, resource_version=1
    )
    receipt = await service.approve(pending.request_id, nonce="n1")

    first = await service.verify(
        receipt, session_id="s1", tool_name="send_email", arguments={"to": "alice"}
    )
    second = await service.verify(
        receipt, session_id="s1", tool_name="send_email", arguments={"to": "alice"}
    )
    assert first is True
    assert second is False  # replay of an already-redeemed receipt


async def test_verify_rejects_a_receipt_for_the_wrong_call() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="send_email", arguments={"to": "alice"}, resource_version=1
    )
    receipt = await service.approve(pending.request_id, nonce="n1")

    ok = await service.verify(
        receipt, session_id="s1", tool_name="send_email", arguments={"to": "mallory"}
    )
    assert ok is False


async def test_verify_rejects_a_non_receipt_object() -> None:
    service = _service()
    ok = await service.verify(
        "not-a-receipt", session_id="s1", tool_name="send_email", arguments={}
    )
    assert ok is False


async def test_verify_enforces_resource_version_binding() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="transfer_funds", arguments={"amount": 10}, resource_version=5
    )
    receipt = await service.approve(pending.request_id, nonce="n1")

    stale = await service.verify(
        receipt,
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"amount": 10},
        resource_version=6,  # the account's balance moved on after approval
    )
    assert stale is False

    fresh = await service.verify(
        receipt,
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"amount": 10},
        resource_version=5,
    )
    assert fresh is True


async def test_denied_approval_cannot_later_be_approved() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="t", arguments={}, resource_version=0
    )
    await service.deny(pending.request_id)
    with pytest.raises(ApprovalAlreadyResolvedError):
        await service.approve(pending.request_id, nonce="n1")


async def test_approving_an_already_approved_request_raises() -> None:
    service = _service()
    pending = await service.request_approval(
        session_id="s1", tool_name="t", arguments={}, resource_version=0
    )
    await service.approve(pending.request_id, nonce="n1")
    with pytest.raises(ApprovalAlreadyResolvedError):
        await service.approve(pending.request_id, nonce="n2")


async def test_approving_an_unknown_request_raises() -> None:
    service = _service()
    with pytest.raises(ApprovalNotFoundError):
        await service.approve("does-not-exist", nonce="n1")


async def test_drain_pending_expires_everything_still_pending() -> None:
    service = _service()
    p1 = await service.request_approval(
        session_id="s1", tool_name="t1", arguments={}, resource_version=0
    )
    p2 = await service.request_approval(
        session_id="s1", tool_name="t2", arguments={}, resource_version=0
    )
    await service.approve(p1.request_id, nonce="n1")  # already resolved, must not be drained

    drained = await service.drain_pending()
    assert [a.request_id for a in drained] == [p2.request_id]

    refreshed_p2 = await service.queue.get(p2.request_id)
    assert refreshed_p2 is not None
    assert refreshed_p2.status is ApprovalStatus.EXPIRED

    with pytest.raises(ApprovalAlreadyResolvedError):
        await service.approve(p2.request_id, nonce="n3")  # can no longer be approved after drain


async def test_verify_satisfies_the_gateway_receipt_verifier_protocol_structurally() -> None:
    """`ApprovalService.verify`'s signature -- an async method accepting a
    receipt plus `session_id`/`tool_name`/`arguments` keyword arguments and
    returning `bool` -- must be assignable wherever
    `agentshield_gateway.boundaries.ReceiptVerifier` is expected, with zero
    import-time coupling in either direction. This exercises that by
    actually running one call through a real `DecisionPipeline`.
    """
    from agentshield_approvals.tiering import ApprovalTier, ConsequenceTieringPolicy
    from agentshield_core.labels import Label
    from agentshield_gateway.dispatch import InMemoryToolDispatcher
    from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
    from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
    from agentshield_gateway.session import GatewaySession
    from agentshield_ledger.ledger import Ledger
    from agentshield_policy.mcp_schema import generate_schema
    from agentshield_policy.pdp import PolicyDecisionPoint
    from agentshield_policy.policies import PolicyStore

    tool = {
        "name": "send_email",
        "description": "Send an email",
        "inputSchema": {
            "type": "object",
            "properties": {"to": {"type": "string"}},
            "required": ["to"],
        },
    }
    schema = generate_schema([tool])
    store = PolicyStore(policy_text="permit(principal, action, resource);", schema=schema)
    pdp = PolicyDecisionPoint(schema, store)
    registry = ToolRegistry()
    registry.register("send_email", ToolSecurityProfile(ceiling=Label.bottom(), trifecta_leg=None))

    tiering = ConsequenceTieringPolicy()
    tiering.register("send_email", ApprovalTier.HIGH)  # every call requires sign-off

    approvals = _service()

    from agentshield_core.capabilities import Capability

    session = GatewaySession(session_id="s1")
    from agentshield_gateway.schema_pinning import PinnedToolSet

    session.pinned_tools = PinnedToolSet.pin([tool])
    session.grant_capability(
        Capability.mint(session_id="s1", tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )

    pipeline = DecisionPipeline(
        policy_decision_point=pdp,
        ledger=Ledger(signing_key=Ed25519PrivateKey.generate()),
        tool_registry=registry,
        approval_policy=tiering,
        receipt_verifier=approvals,  # the cross-package duck-typing under test
    )
    dispatcher = InMemoryToolDispatcher()
    dispatcher.register("send_email", lambda args: _ok({"sent": True}))

    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        raw_context={"principal": "s1"},
        current_tool_schema=tool,
    )

    denied = await pipeline.evaluate_and_dispatch(request, session, dispatcher)
    assert denied.decision.stage == "receipt"
    assert denied.status is OutcomeStatus.DENIED

    pending = await approvals.request_approval(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        resource_version=0,
    )
    receipt = await approvals.approve(pending.request_id, nonce="approval-nonce-1")

    request_with_receipt = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        raw_context={"principal": "s1"},
        current_tool_schema=tool,
        receipt=receipt,
    )
    allowed = await pipeline.evaluate_and_dispatch(request_with_receipt, session, dispatcher)
    assert allowed.status is OutcomeStatus.DISPATCHED
    assert allowed.decision.stage == "receipt"


async def _ok(result: dict[str, object]) -> dict[str, object]:
    return result
