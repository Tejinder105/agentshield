"""Pydantic request/response wire models for the console API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RegisterPolicyRequest(BaseModel):
    tools: list[dict[str, Any]] = Field(default_factory=list)
    policy_text: str


class PolicyView(BaseModel):
    session_id: str
    policy_text: str


class ValidatePolicyRequest(BaseModel):
    policy_text: str


class ValidatePolicyResponse(BaseModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)


class ProposePolicyRequest(BaseModel):
    policy_text: str


class ProposePolicyResponse(BaseModel):
    decision: str  # ALLOW | DENY | REQUIRE_APPROVAL
    stage: str
    reason: str
    applied: bool
    subsumption_report: dict[str, Any] | None = None


class PendingApprovalView(BaseModel):
    request_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    resource_version: int
    requested_at: float
    status: str


class ApproveRequest(BaseModel):
    nonce: str


class ReceiptView(BaseModel):
    payload: dict[str, Any]
    signature: str


class AuditEntryResponse(BaseModel):
    seq: int
    event_type: str
    payload: dict[str, Any]
    ts: int | None


class AuditSessionResponse(BaseModel):
    session_id: str
    chain_intact: bool
    entries: list[AuditEntryResponse]


class ReplaySessionResponse(BaseModel):
    session_id: str
    chain_intact: bool
    final_decision: str | None
    steps: list[AuditEntryResponse]


class KillSwitchRequest(BaseModel):
    reason: str


class BlastRadiusEntryResponse(BaseModel):
    seq: int
    entry_hash: str
    session_id: str | None
    tool_name: str | None
    status: str | None
    ts: int | None


class KillSwitchResponse(BaseModel):
    scope: str
    reason: str
    triggered_at: int
    session_id: str | None
    new_global_epoch: int | None
    new_session_epoch: int | None
    blast_radius: list[BlastRadiusEntryResponse]
