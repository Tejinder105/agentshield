from __future__ import annotations

from collections.abc import Generator

import pytest
from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_gateway.dispatch import InMemoryToolDispatcher, ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.schema_pinning import PinnedToolSet
from agentshield_gateway.session import GatewaySession
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Tracer

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

#: Alice-only, exactly like `agentshield-gateway`'s own fixtures -- this
#: package tests the *instrumentation*, not Cedar itself, so one simple,
#: well-understood policy is all that is needed.
ALICE_ONLY_SEND_EMAIL = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.to == "alice@example.com" };
"""


@pytest.fixture
def exporter() -> InMemorySpanExporter:
    return InMemorySpanExporter()


@pytest.fixture
def tracer(exporter: InMemorySpanExporter) -> Generator[Tracer, None, None]:
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("agentshield-observability-tests")
    provider.shutdown()


@pytest.fixture
def sample_schema() -> GeneratedSchema:
    return generate_schema([SEND_EMAIL_TOOL])


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
    return registry


@pytest.fixture
def pipeline(
    sample_schema: GeneratedSchema, ledger: Ledger, tool_registry: ToolRegistry
) -> DecisionPipeline:
    store = PolicyStore(policy_text=ALICE_ONLY_SEND_EMAIL, schema=sample_schema)
    pdp = PolicyDecisionPoint(sample_schema, store)
    return DecisionPipeline(policy_decision_point=pdp, ledger=ledger, tool_registry=tool_registry)


@pytest.fixture
def authorized_session() -> GatewaySession:
    session = GatewaySession(session_id="s1")
    session.pinned_tools = PinnedToolSet.pin([SEND_EMAIL_TOOL])
    session.grant_capability(
        Capability.mint(session_id="s1", tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )
    return session


@pytest.fixture
def dispatcher() -> ToolDispatcher:
    d = InMemoryToolDispatcher()
    d.register("send_email", lambda args: _echo(args))
    return d


async def _echo(args: dict[str, object]) -> dict[str, object]:
    return {"sent_to": args["to"]}
