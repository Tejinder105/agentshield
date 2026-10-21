from __future__ import annotations

import pytest
from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_gateway.pipeline import DecisionPipeline
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.schema_pinning import PinnedToolSet
from agentshield_gateway.session import GatewaySession, SessionStore
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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

TRANSFER_FUNDS_TOOL: dict[str, object] = {
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

ALLOW_ALICE_AND_SMALL_TRANSFERS = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.to == "alice@example.com" };

permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"transfer_funds",
    resource == AgentShield::Tool::"transfer_funds"
) when { context.input.amount_usd <= 100 };
"""


@pytest.fixture
def sample_tools() -> list[dict[str, object]]:
    return [SEND_EMAIL_TOOL, TRANSFER_FUNDS_TOOL]


@pytest.fixture
def sample_schema(sample_tools: list[dict[str, object]]) -> GeneratedSchema:
    return generate_schema(sample_tools)


@pytest.fixture
def policy_decision_point(sample_schema: GeneratedSchema) -> PolicyDecisionPoint:
    store = PolicyStore(policy_text=ALLOW_ALICE_AND_SMALL_TRANSFERS, schema=sample_schema)
    return PolicyDecisionPoint(sample_schema, store)


@pytest.fixture
def ledger() -> Ledger:
    return Ledger(signing_key=Ed25519PrivateKey.generate())


@pytest.fixture
def tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        "send_email",
        ToolSecurityProfile(
            ceiling=Label.private(), trifecta_leg=TrifectaLeg.EXTERNAL_COMMUNICATION
        ),
    )
    registry.register(
        "transfer_funds",
        ToolSecurityProfile(ceiling=Label.bottom(), trifecta_leg=None),
    )
    return registry


@pytest.fixture
def pipeline(
    policy_decision_point: PolicyDecisionPoint, ledger: Ledger, tool_registry: ToolRegistry
) -> DecisionPipeline:
    return DecisionPipeline(
        policy_decision_point=policy_decision_point, ledger=ledger, tool_registry=tool_registry
    )


@pytest.fixture
def sessions() -> SessionStore:
    return SessionStore()


@pytest.fixture
def authorized_session(sample_tools: list[dict[str, object]]) -> GatewaySession:
    """A session with send_email pinned and a fresh, unexpired, epoch-0
    capability granted -- i.e. everything steps 1-3 need to already be
    satisfied, so individual pipeline tests can focus on one stage at a
    time.
    """
    session = GatewaySession(session_id="s1")
    session.pinned_tools = PinnedToolSet.pin(sample_tools)
    session.grant_capability(
        Capability.mint(session_id="s1", tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )
    session.grant_capability(
        Capability.mint(session_id="s1", tool_name="transfer_funds", epoch=0, ttl_seconds=300.0)
    )
    return session
