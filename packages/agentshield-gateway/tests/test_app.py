from __future__ import annotations

from typing import Any

import httpx
import pytest
from agentshield_gateway.app import create_app
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.session import SessionStore
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio

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

ALLOW_ALICE_ONLY = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.to == "alice@example.com" };
"""


async def _make_client() -> httpx.AsyncClient:
    schema: GeneratedSchema = generate_schema([SEND_EMAIL_TOOL])
    store = PolicyStore(policy_text=ALLOW_ALICE_ONLY, schema=schema)
    pdp = PolicyDecisionPoint(schema, store)
    registry = ToolRegistry()
    registry.register("send_email", ToolSecurityProfile())
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    pipeline = DecisionPipeline(policy_decision_point=pdp, ledger=ledger, tool_registry=registry)
    sessions = SessionStore()
    dispatcher = InMemoryToolDispatcher()

    async def _send_email(args: dict[str, Any]) -> dict[str, Any]:
        return {"sent": True, "to": args.get("to")}

    dispatcher.register("send_email", _send_email)

    app = create_app(pipeline=pipeline, sessions=sessions, dispatcher=dispatcher)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://gateway.test")


async def test_healthz() -> None:
    async with await _make_client() as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


async def test_full_session_lifecycle_allows_an_authorized_call() -> None:
    async with await _make_client() as client:
        create = await client.post(
            "/sessions", json={"session_id": "s1", "tools": [SEND_EMAIL_TOOL]}
        )
        assert create.status_code == 201
        assert create.json() == {"session_id": "s1", "pinned_tool_count": 1}

        grant = await client.post(
            "/sessions/s1/capabilities", json={"tool_name": "send_email", "ttl_seconds": 300}
        )
        assert grant.status_code == 201
        assert "capability_id" in grant.json()

        call = await client.post(
            "/sessions/s1/tools/send_email/call",
            headers={"x-agent-shield-principal": "s1"},
            json={
                "arguments": {"to": "alice@example.com", "body": "hi"},
                "current_tool_schema": SEND_EMAIL_TOOL,
            },
        )
        assert call.status_code == 200
        body = call.json()
        assert body["decision"] == "ALLOW"
        assert body["status"] == "dispatched"
        assert body["result"] == {"sent": True, "to": "alice@example.com"}


async def test_call_without_capability_is_denied() -> None:
    async with await _make_client() as client:
        await client.post("/sessions", json={"session_id": "s1", "tools": [SEND_EMAIL_TOOL]})
        call = await client.post(
            "/sessions/s1/tools/send_email/call",
            headers={"x-agent-shield-principal": "s1"},
            json={
                "arguments": {"to": "alice@example.com", "body": "hi"},
                "current_tool_schema": SEND_EMAIL_TOOL,
            },
        )
        assert call.status_code == 200
        body = call.json()
        assert body["decision"] == "DENY"
        assert body["stage"] == "capability"


async def test_call_for_unknown_session_is_404() -> None:
    async with await _make_client() as client:
        response = await client.post(
            "/sessions/does-not-exist/tools/send_email/call",
            json={"arguments": {}},
        )
        assert response.status_code == 404


async def test_cedar_policy_violation_denies_through_http() -> None:
    async with await _make_client() as client:
        await client.post("/sessions", json={"session_id": "s1", "tools": [SEND_EMAIL_TOOL]})
        await client.post(
            "/sessions/s1/capabilities", json={"tool_name": "send_email", "ttl_seconds": 300}
        )
        call = await client.post(
            "/sessions/s1/tools/send_email/call",
            headers={"x-agent-shield-principal": "s1"},
            json={
                "arguments": {"to": "mallory@example.com", "body": "hi"},
                "current_tool_schema": SEND_EMAIL_TOOL,
            },
        )
        body = call.json()
        assert body["decision"] == "DENY"
        assert body["stage"] == "cedar_policy"
