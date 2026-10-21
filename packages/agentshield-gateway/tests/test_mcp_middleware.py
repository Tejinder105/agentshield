from __future__ import annotations

from typing import Any, cast

import pytest
from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_gateway.mcp_middleware import AgentShieldMiddleware
from agentshield_gateway.pipeline import DecisionPipeline
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.session import SessionStore
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server.context import ServerRequestContext
from mcp.server.session import ServerSession
from mcp.types import CallToolResult, TextContent

pytestmark = pytest.mark.asyncio

SEND_EMAIL_TOOL = {
    "name": "send_email",
    "description": "Send an email on the user's behalf",
    "inputSchema": {"type": "object"},
}

# The mcp v2 middleware derives its own session id from the live
# `ServerSession` object identity rather than any fixed string (see
# `AgentShieldMiddleware._resolve_session_id`), so these tests need a Cedar
# policy that is principal-agnostic -- the shared `pipeline` fixture from
# `conftest.py` is scoped to a fixed `"s1"` principal and is not reusable
# here.
PERMIT_ALL = "permit(principal, action, resource);"


def _permissive_pipeline() -> DecisionPipeline:
    schema = generate_schema([SEND_EMAIL_TOOL])
    store = PolicyStore(policy_text=PERMIT_ALL, schema=schema)
    pdp = PolicyDecisionPoint(schema, store)
    registry = ToolRegistry()
    registry.register("send_email", ToolSecurityProfile(ceiling=Label.bottom(), trifecta_leg=None))
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    return DecisionPipeline(policy_decision_point=pdp, ledger=ledger, tool_registry=registry)


def _ctx(*, method: str = "tools/call", params: dict[str, Any] | None = None) -> Any:
    # A bare `object()` stands in for the real `ServerSession` -- these
    # tests never touch any `ServerSession` method, only `id(ctx.session)`
    # for session-identity resolution, so a plain sentinel object is
    # enough; `cast` tells mypy that deliberately, instead of weakening
    # `ServerRequestContext`'s own field type for production callers.
    return ServerRequestContext(
        session=cast(ServerSession, object()),
        lifespan_context=None,
        protocol_version="2026-07-28",
        method=method,
        params=params,
    )


def _middleware(pipeline: DecisionPipeline, sessions: SessionStore) -> AgentShieldMiddleware:
    return AgentShieldMiddleware(
        pipeline=pipeline, sessions=sessions, default_tools=[SEND_EMAIL_TOOL]
    )


async def test_non_tools_call_methods_pass_through_untouched(sessions: SessionStore) -> None:
    middleware = _middleware(_permissive_pipeline(), sessions)
    ctx = _ctx(method="tools/list", params=None)

    sentinel = {"passed": "through"}

    async def call_next(_ctx: Any) -> Any:
        return sentinel

    result = await middleware(ctx, call_next)
    assert result is sentinel


async def test_denied_call_never_reaches_call_next(sessions: SessionStore) -> None:
    middleware = _middleware(_permissive_pipeline(), sessions)
    ctx = _ctx(params={"name": "send_email", "arguments": {"to": "alice@example.com"}})
    # No capability has been granted for this (new) session -> step 2 denies.

    call_next_invoked = False

    async def call_next(_ctx: Any) -> Any:
        nonlocal call_next_invoked
        call_next_invoked = True
        return CallToolResult(content=[TextContent(type="text", text="ok")])

    result = await middleware(ctx, call_next)
    assert call_next_invoked is False
    assert isinstance(result, CallToolResult)
    assert result.is_error is True
    content = result.content[0]
    assert isinstance(content, TextContent)
    assert "agent-shield" in content.text


async def test_authorized_call_reaches_call_next_and_returns_its_result(
    sessions: SessionStore,
) -> None:
    middleware = _middleware(_permissive_pipeline(), sessions)
    ctx = _ctx(params={"name": "send_email", "arguments": {"to": "alice@example.com"}})
    session_id = f"mcp-session-{id(ctx.session)}"
    session = sessions.get_or_create(session_id)
    session.grant_capability(
        Capability.mint(session_id=session_id, tool_name="send_email", epoch=0, ttl_seconds=300.0)
    )

    real_result = CallToolResult(content=[TextContent(type="text", text="sent!")])

    async def call_next(_ctx: Any) -> Any:
        return real_result

    result = await middleware(ctx, call_next)
    assert result is real_result


async def test_unknown_tool_name_type_passes_through(sessions: SessionStore) -> None:
    middleware = _middleware(_permissive_pipeline(), sessions)
    ctx = _ctx(params={"name": 12345, "arguments": {}})

    async def call_next(_ctx: Any) -> Any:
        return "passed-through"

    result = await middleware(ctx, call_next)
    # `call_next` here deliberately returns a plain `str`, outside
    # `HandlerResult`'s own declared domain, to prove this passthrough
    # branch returns whatever `call_next` produced completely unexamined
    # -- hence the explicit `type: ignore`, not a real typing bug.
    assert result == "passed-through"  # type: ignore[comparison-overlap]
