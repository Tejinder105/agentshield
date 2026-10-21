"""Proves, with a real `DecisionPipeline`, that `agentshield-revocation`'s
`EpochStore` satisfies `agentshield_gateway.boundaries.EpochSource`
structurally -- zero import coupling in either direction -- and that a
global kill switch, wired to a real `agentshield-approvals` `ApprovalService`
and a real capability minted under epoch 0, actually denies a previously
valid call the moment it fires.
"""

from __future__ import annotations

import pytest
from agentshield_approvals.nonce_store import InMemoryNonceStore
from agentshield_approvals.queue import InMemoryPendingApprovalQueue
from agentshield_approvals.service import ApprovalService
from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.schema_pinning import PinnedToolSet
from agentshield_gateway.session import GatewaySession
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from agentshield_revocation.epoch_store import InMemoryEpochStore
from agentshield_revocation.kill_switch import KillSwitch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio

_SEND_EMAIL_TOOL = {
    "name": "send_email",
    "description": "Send an email",
    "inputSchema": {
        "type": "object",
        "properties": {"to": {"type": "string"}},
        "required": ["to"],
    },
}


def _dispatcher() -> InMemoryToolDispatcher:
    dispatcher = InMemoryToolDispatcher()
    dispatcher.register("send_email", lambda args: _ok({"sent": True}))
    return dispatcher


async def _ok(result: dict[str, object]) -> dict[str, object]:
    return result


def _pipeline(epoch_store: InMemoryEpochStore, ledger: Ledger) -> DecisionPipeline:
    schema = generate_schema([_SEND_EMAIL_TOOL])
    store = PolicyStore(policy_text="permit(principal, action, resource);", schema=schema)
    pdp = PolicyDecisionPoint(schema, store)
    registry = ToolRegistry()
    registry.register("send_email", ToolSecurityProfile(ceiling=Label.bottom(), trifecta_leg=None))
    return DecisionPipeline(
        policy_decision_point=pdp,
        ledger=ledger,
        tool_registry=registry,
        epoch_source=epoch_store,  # the cross-package duck-typing under test
    )


def _session() -> GatewaySession:
    session = GatewaySession(session_id="s1")
    session.pinned_tools = PinnedToolSet.pin([_SEND_EMAIL_TOOL])
    session.grant_capability(
        Capability.mint(session_id="s1", tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )
    return session


async def test_epoch_store_satisfies_the_gateway_epoch_source_protocol_structurally() -> None:
    epoch_store = InMemoryEpochStore()
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    pipeline = _pipeline(epoch_store, ledger)
    session = _session()
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        raw_context={"principal": "s1"},
        current_tool_schema=_SEND_EMAIL_TOOL,
    )

    allowed = await pipeline.evaluate_and_dispatch(request, session, _dispatcher())
    assert allowed.status is OutcomeStatus.DISPATCHED


async def test_global_kill_switch_denies_a_previously_valid_capability() -> None:
    epoch_store = InMemoryEpochStore()
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    pipeline = _pipeline(epoch_store, ledger)
    session = _session()  # capability minted under epoch 0
    request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        raw_context={"principal": "s1"},
        current_tool_schema=_SEND_EMAIL_TOOL,
    )

    before = await pipeline.evaluate_and_dispatch(request, session, _dispatcher())
    assert before.status is OutcomeStatus.DISPATCHED

    switch = KillSwitch(epoch_store=epoch_store, ledger=ledger)
    await switch.trigger_global(reason="suspected compromise")

    after = await pipeline.evaluate_and_dispatch(request, session, _dispatcher())
    assert after.status is OutcomeStatus.DENIED
    assert after.decision.stage == "capability"


async def test_global_kill_switch_drains_a_real_approval_service() -> None:
    """`ApprovalService.drain_pending` is what `KillSwitch.trigger_global`
    calls through `ApprovalDrain` -- again, structurally, with no import
    of `agentshield-approvals` from this package's source.
    """
    key = Ed25519PrivateKey.generate()
    approvals = ApprovalService(
        signing_key=key,
        public_key_hex=key.public_key().public_bytes_raw().hex(),
        queue=InMemoryPendingApprovalQueue(),
        nonce_store=InMemoryNonceStore(),
    )
    pending = await approvals.request_approval(
        session_id="s1", tool_name="transfer_funds", arguments={"amount": 1000}, resource_version=0
    )

    switch = KillSwitch(epoch_store=InMemoryEpochStore(), approval_drain=approvals)
    result = await switch.trigger_global(reason="incident")

    assert [r.request_id for r in result.drained_approvals] == [pending.request_id]
    refreshed = await approvals.queue.get(pending.request_id)
    assert refreshed is not None
    assert refreshed.status.value == "expired"


async def test_session_scoped_kill_switch_leaves_other_sessions_untouched() -> None:
    epoch_store = InMemoryEpochStore()
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    pipeline = _pipeline(epoch_store, ledger)

    victim_session = _session()
    victim_request = ToolCallRequest(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        raw_context={"principal": "s1"},
        current_tool_schema=_SEND_EMAIL_TOOL,
    )

    switch = KillSwitch(epoch_store=epoch_store)
    await switch.trigger_session("s1", reason="anomalous volume on s1")

    denied = await pipeline.evaluate_and_dispatch(victim_request, victim_session, _dispatcher())
    assert denied.status is OutcomeStatus.DENIED
    assert denied.decision.stage == "capability"

    other_session = GatewaySession(session_id="s2")
    other_session.pinned_tools = PinnedToolSet.pin([_SEND_EMAIL_TOOL])
    other_session.grant_capability(
        Capability.mint(session_id="s2", tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )
    other_request = ToolCallRequest(
        session_id="s2",
        tool_name="send_email",
        arguments={"to": "bob@example.com"},
        raw_context={"principal": "s2"},
        current_tool_schema=_SEND_EMAIL_TOOL,
    )
    unaffected = await pipeline.evaluate_and_dispatch(other_request, other_session, _dispatcher())
    assert unaffected.status is OutcomeStatus.DISPATCHED
