"""The FastAPI ASGI app behind `apps/console`.

Mirrors `agentshield_gateway.app.create_app`'s dependency-injection shape
(every collaborator is a constructor parameter, not built here) so a
deployment or a test can choose exactly which policy registry, approval
service, ledger, and kill switch back a given instance -- real or
in-memory, Redis-backed or not.
"""

from __future__ import annotations

from agentshield_approvals.service import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    ApprovalService,
)
from agentshield_core.decision import Decision, DecisionKind, ObligationKind
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import SchemaGenerationError, generate_schema
from agentshield_policy.policies import PolicyValidationError
from agentshield_revocation.blast_radius import BlastRadiusReport, build_blast_radius_report
from agentshield_revocation.kill_switch import KillSwitch, KillSwitchResult
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse

from agentshield_console_api.audit import chain_intact, session_entries
from agentshield_console_api.policies import PolicyRegistry, UnknownSessionError
from agentshield_console_api.replay import replay_session
from agentshield_console_api.schemas import (
    ApproveRequest,
    AuditEntryResponse,
    AuditSessionResponse,
    BlastRadiusEntryResponse,
    KillSwitchRequest,
    KillSwitchResponse,
    PendingApprovalView,
    PolicyView,
    ProposePolicyRequest,
    ProposePolicyResponse,
    ReceiptView,
    RegisterPolicyRequest,
    ReplaySessionResponse,
    ValidatePolicyRequest,
    ValidatePolicyResponse,
)
from agentshield_console_api.sse import approval_queue_events, approval_to_dict


def create_app(
    *,
    policy_registry: PolicyRegistry,
    approval_service: ApprovalService,
    ledger: Ledger,
    kill_switch: KillSwitch,
    blast_radius_window_seconds: float = 3600.0,
    approval_stream_poll_interval_seconds: float = 1.0,
    approval_stream_max_iterations: int | None = None,
) -> FastAPI:
    """`approval_stream_poll_interval_seconds` and
    `approval_stream_max_iterations` exist to make `/approvals/stream`
    testable at all: `httpx.ASGITransport` drives an ASGI app's `__call__`
    to full completion *before* it ever returns a response object to the
    caller (unlike a real socket, where a client can read a response
    incrementally while the server is still producing it), so a test
    cannot observe even one event from a genuinely unbounded stream
    through it. Production callers never pass `approval_stream_max_
    iterations`, and the stream runs until the client disconnects, exactly
    as `agentshield_console_api.sse.approval_queue_events`'s own docstring
    describes.
    """
    app = FastAPI(title="Agent Shield Console API")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # --- Policy editor and validator ------------------------------------

    @app.post("/sessions/{session_id}/policy", status_code=201, response_model=PolicyView)
    async def register_policy(session_id: str, body: RegisterPolicyRequest) -> PolicyView:
        try:
            schema = generate_schema(body.tools)
        except SchemaGenerationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            session_policy = policy_registry.register(
                session_id, schema=schema, policy_text=body.policy_text
            )
        except PolicyValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return PolicyView(session_id=session_id, policy_text=session_policy.store.policy_text)

    @app.get("/sessions/{session_id}/policy", response_model=PolicyView)
    async def get_policy(session_id: str) -> PolicyView:
        session_policy = policy_registry.get(session_id)
        if session_policy is None:
            raise HTTPException(status_code=404, detail="unknown session")
        return PolicyView(session_id=session_id, policy_text=session_policy.store.policy_text)

    @app.post("/sessions/{session_id}/policy/validate", response_model=ValidatePolicyResponse)
    async def validate_policy(
        session_id: str, body: ValidatePolicyRequest
    ) -> ValidatePolicyResponse:
        try:
            result = policy_registry.validate(session_id, body.policy_text)
        except UnknownSessionError as exc:
            raise HTTPException(status_code=404, detail="unknown session") from exc
        return ValidatePolicyResponse(valid=result.valid, errors=list(result.errors))

    @app.put("/sessions/{session_id}/policy", response_model=ProposePolicyResponse)
    async def propose_policy(session_id: str, body: ProposePolicyRequest) -> ProposePolicyResponse:
        try:
            decision = policy_registry.propose_update(session_id, body.policy_text)
        except UnknownSessionError as exc:
            raise HTTPException(status_code=404, detail="unknown session") from exc
        return _propose_response(decision)

    # --- Live approval queue ----------------------------------------------

    @app.get("/approvals", response_model=list[PendingApprovalView])
    async def list_approvals() -> list[PendingApprovalView]:
        pending = await approval_service.queue.list_pending()
        return [PendingApprovalView(**approval_to_dict(a)) for a in pending]

    @app.get("/approvals/stream")
    async def stream_approvals() -> StreamingResponse:
        return StreamingResponse(
            approval_queue_events(
                approval_service.queue,
                poll_interval_seconds=approval_stream_poll_interval_seconds,
                max_iterations=approval_stream_max_iterations,
            ),
            media_type="text/event-stream",
        )

    @app.post("/approvals/{request_id}/approve", response_model=ReceiptView)
    async def approve(request_id: str, body: ApproveRequest) -> ReceiptView:
        try:
            receipt = await approval_service.approve(request_id, nonce=body.nonce)
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except ApprovalAlreadyResolvedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return ReceiptView(payload=receipt.payload.to_dict(), signature=receipt.signature_hex)

    @app.post("/approvals/{request_id}/deny", response_model=PendingApprovalView)
    async def deny(request_id: str) -> PendingApprovalView:
        try:
            approval = await approval_service.deny(request_id)
        except ApprovalNotFoundError as exc:
            raise HTTPException(status_code=404, detail="unknown approval request") from exc
        except ApprovalAlreadyResolvedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return PendingApprovalView(**approval_to_dict(approval))

    # --- Audit explorer and deterministic replay ---------------------------

    @app.get("/audit/sessions/{session_id}", response_model=AuditSessionResponse)
    async def audit_session(session_id: str) -> AuditSessionResponse:
        entries = ledger.entries
        views = session_entries(entries, session_id)
        return AuditSessionResponse(
            session_id=session_id,
            chain_intact=chain_intact(entries),
            entries=[
                AuditEntryResponse(seq=v.seq, event_type=v.event_type, payload=v.payload, ts=v.ts)
                for v in views
            ],
        )

    @app.get("/audit/sessions/{session_id}/replay", response_model=ReplaySessionResponse)
    async def audit_replay(session_id: str) -> ReplaySessionResponse:
        replay = replay_session(ledger.entries, session_id)
        return ReplaySessionResponse(
            session_id=replay.session_id,
            chain_intact=replay.chain_intact,
            final_decision=replay.final_decision,
            steps=[
                AuditEntryResponse(seq=s.seq, event_type=s.event_type, payload=s.payload, ts=s.ts)
                for s in replay.steps
            ],
        )

    # --- Emergency revocation (kill switch) ---------------------------------

    @app.post("/kill-switch/global", response_model=KillSwitchResponse)
    async def kill_switch_global(body: KillSwitchRequest) -> KillSwitchResponse:
        result = await kill_switch.trigger_global(reason=body.reason)
        return _kill_switch_response(result)

    @app.post("/kill-switch/sessions/{session_id}", response_model=KillSwitchResponse)
    async def kill_switch_session(session_id: str, body: KillSwitchRequest) -> KillSwitchResponse:
        result = await kill_switch.trigger_session(session_id, reason=body.reason)
        return _kill_switch_response(result)

    def _kill_switch_response(result: KillSwitchResult) -> KillSwitchResponse:
        window_start = int(result.triggered_at - blast_radius_window_seconds)
        report = build_blast_radius_report(
            ledger.entries,
            window_start=min(window_start, result.triggered_at),
            window_end=result.triggered_at,
        )
        return KillSwitchResponse(
            scope=result.scope,
            reason=result.reason,
            triggered_at=result.triggered_at,
            session_id=result.session_id,
            new_global_epoch=result.new_global_epoch,
            new_session_epoch=result.new_session_epoch,
            blast_radius=_blast_radius_views(report),
        )

    return app


def _propose_response(decision: Decision) -> ProposePolicyResponse:
    subsumption_report = None
    for obligation in decision.obligations:
        if obligation.kind is ObligationKind.RECORD_SUBSUMPTION_EVIDENCE:
            subsumption_report = obligation.detail.get("report")
    return ProposePolicyResponse(
        decision=decision.kind.value,
        stage=decision.stage,
        reason=decision.reason,
        applied=decision.kind is DecisionKind.ALLOW,
        subsumption_report=subsumption_report,
    )


def _blast_radius_views(report: BlastRadiusReport) -> list[BlastRadiusEntryResponse]:
    return [
        BlastRadiusEntryResponse(
            seq=e.seq,
            entry_hash=e.entry_hash,
            session_id=e.session_id,
            tool_name=e.tool_name,
            status=e.status,
            ts=e.ts,
        )
        for e in report.entries
    ]
