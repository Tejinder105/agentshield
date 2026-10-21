"""The FastAPI HTTP surface for the gateway.

This exposes session lifecycle (pin a tool list, grant a capability) and a
direct `tools/{name}/call` endpoint that runs the full decision pipeline.
It is a real, independently useful HTTP API in its own right (e.g. for an
SDK that talks HTTP rather than MCP), and it is also what the
`agentshield_gateway.mcp_middleware` module's downstream `tools/call`
interception conceptually mirrors -- the two surfaces share the exact same
`DecisionPipeline`, so a call denied through one is denied through the
other for identical reasons.
"""

from __future__ import annotations

from typing import Any

from agentshield_core.capabilities import Capability
from agentshield_core.labels import Confidentiality, Integrity, Label
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, ToolCallRequest
from agentshield_gateway.schema_pinning import PinnedToolSet
from agentshield_gateway.session import SessionStore


class CreateSessionRequest(BaseModel):
    session_id: str
    tools: list[dict[str, Any]] = Field(default_factory=list)


class CreateSessionResponse(BaseModel):
    session_id: str
    pinned_tool_count: int


class GrantCapabilityRequest(BaseModel):
    tool_name: str
    epoch: int = 0
    ttl_seconds: float = 300.0


class GrantCapabilityResponse(BaseModel):
    capability_id: str


class ToolCallBody(BaseModel):
    arguments: dict[str, Any] = Field(default_factory=dict)
    current_tool_schema: dict[str, Any] | None = None
    input_integrity: str = "TRUSTED"
    input_confidentiality: str = "PUBLIC"
    receipt: Any | None = None


class ToolCallResponse(BaseModel):
    decision: str
    stage: str
    reason: str
    status: str
    result: dict[str, Any] | None = None


def create_app(
    *, pipeline: DecisionPipeline, sessions: SessionStore, dispatcher: ToolDispatcher
) -> FastAPI:
    """Build the ASGI app. `pipeline`, `sessions`, and `dispatcher` are
    injected rather than constructed here so a deployment (or a test) can
    choose exactly which collaborators -- real Cedar policies, a real
    downstream dispatcher, an in-memory one for CI -- back this instance.
    """
    app = FastAPI(title="Agent Shield Gateway")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/sessions", status_code=201, response_model=CreateSessionResponse)
    async def create_session(body: CreateSessionRequest) -> CreateSessionResponse:
        session = sessions.get_or_create(body.session_id)
        session.pinned_tools = PinnedToolSet.pin(body.tools)
        return CreateSessionResponse(
            session_id=session.session_id, pinned_tool_count=len(session.pinned_tools.digests)
        )

    @app.post(
        "/sessions/{session_id}/capabilities",
        status_code=201,
        response_model=GrantCapabilityResponse,
    )
    async def grant_capability(
        session_id: str, body: GrantCapabilityRequest
    ) -> GrantCapabilityResponse:
        session = sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="unknown session")
        capability = Capability.mint(
            session_id=session_id,
            tool_name=body.tool_name,
            epoch=body.epoch,
            ttl_seconds=body.ttl_seconds,
        )
        session.grant_capability(capability)
        return GrantCapabilityResponse(capability_id=capability.capability_id)

    @app.post(
        "/sessions/{session_id}/tools/{tool_name}/call",
        response_model=ToolCallResponse,
    )
    async def call_tool(
        session_id: str, tool_name: str, body: ToolCallBody, request: Request
    ) -> ToolCallResponse:
        session = sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="unknown session")

        call_request = ToolCallRequest(
            session_id=session_id,
            tool_name=tool_name,
            arguments=body.arguments,
            raw_context=dict(request.headers),
            current_tool_schema=body.current_tool_schema,
            input_label=Label(
                integrity=Integrity[body.input_integrity],
                confidentiality=Confidentiality[body.input_confidentiality],
            ),
            receipt=body.receipt,
        )
        outcome = await pipeline.evaluate_and_dispatch(call_request, session, dispatcher)
        return ToolCallResponse(
            decision=outcome.decision.kind.value,
            stage=outcome.decision.stage,
            reason=outcome.decision.reason,
            status=outcome.status.value,
            result=outcome.result,
        )

    return app
