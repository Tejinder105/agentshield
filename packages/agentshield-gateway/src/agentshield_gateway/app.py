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
from agentshield_core.trifecta import TrifectaLeg
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, ToolCallRequest
from agentshield_gateway.registry import ToolSecurityProfile
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

        for tool in body.tools:
            name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
            if name and pipeline.tool_registry.get(name) is None:
                if name in ("execute_shell", "run_shell", "bash"):
                    profile = ToolSecurityProfile(
                        ceiling=Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PUBLIC),
                        trifecta_leg=TrifectaLeg.EXTERNAL_COMMUNICATION,
                    )
                elif name in ("read_file", "fetch_url", "web_search"):
                    profile = ToolSecurityProfile(
                        ceiling=Label.top(),
                        trifecta_leg=TrifectaLeg.UNTRUSTED_INPUT,
                    )
                else:
                    profile = ToolSecurityProfile(ceiling=Label.top(), trifecta_leg=None)
                pipeline.tool_registry.register(name, profile)

        if body.tools and hasattr(pipeline._pdp, "register_tools"):
            try:
                pipeline._pdp.register_tools(body.tools)
            except Exception:
                pass

        return CreateSessionResponse(
            session_id=session.session_id, pinned_tool_count=len(session.pinned_tools.digests)
        )

    @app.post("/sessions/{session_id}/revoke", status_code=200)
    async def revoke_session(session_id: str) -> dict[str, Any]:
        epoch_source = getattr(pipeline, "_epoch_source", None)
        if hasattr(epoch_source, "bump_session_epoch"):
            new_epoch = await epoch_source.bump_session_epoch(session_id)
            return {"session_id": session_id, "status": "revoked", "epoch": new_epoch}
        elif hasattr(epoch_source, "bump_global_epoch"):
            new_epoch = await epoch_source.bump_global_epoch()
            return {"session_id": session_id, "status": "revoked", "epoch": new_epoch}
        return {"session_id": session_id, "status": "no_epoch_source"}

    @app.get("/sessions/{session_id}/audit")
    async def get_session_audit(session_id: str) -> list[dict[str, Any]]:
        records = []
        ledger = getattr(pipeline, "_ledger", None)
        for entry in getattr(ledger, "entries", []):
            raw_entry = getattr(entry, "entry", {})
            payload = raw_entry.get("payload", {}) if isinstance(raw_entry, dict) else {}
            if isinstance(payload, dict) and payload.get("session_id") == session_id:
                records.append({
                    "seq": entry.seq,
                    "prev_hash": entry.prev_hash,
                    "entry_hash": entry.entry_hash,
                    "payload": payload,
                })
        return records

    @app.get("/audit")
    async def get_all_audit() -> list[dict[str, Any]]:
        records = []
        ledger = getattr(pipeline, "_ledger", None)
        for entry in getattr(ledger, "entries", []):
            raw_entry = getattr(entry, "entry", {})
            payload = raw_entry.get("payload", {}) if isinstance(raw_entry, dict) else {}
            records.append({
                "seq": entry.seq,
                "prev_hash": entry.prev_hash,
                "entry_hash": entry.entry_hash,
                "payload": payload,
            })
        return records

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

    @app.post(
        "/sessions/{session_id}/tools/{tool_name}/authorize",
        response_model=ToolCallResponse,
    )
    async def authorize_tool(
        session_id: str, tool_name: str, body: ToolCallBody, request: Request
    ) -> ToolCallResponse:
        """Authorize a caller-managed action without executing it.

        This is used by integrations whose runtime owns the actual tool
        implementation. The same fail-closed pipeline, capability checks,
        policy checks, information-flow checks, approvals, and audit ledger
        are still applied; only the final downstream dispatch is delegated
        back to the caller.
        """
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
        outcome = await pipeline.evaluate_and_dispatch(
            call_request, session, dispatcher, dispatch=False
        )
        return ToolCallResponse(
            decision=outcome.decision.kind.value,
            stage=outcome.decision.stage,
            reason=outcome.decision.reason,
            status=outcome.status.value,
            result=outcome.result,
        )

    return app
