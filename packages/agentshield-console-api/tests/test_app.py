from __future__ import annotations

from typing import Any

import httpx
import pytest
from agentshield_approvals.nonce_store import InMemoryNonceStore
from agentshield_approvals.queue import InMemoryPendingApprovalQueue
from agentshield_approvals.service import ApprovalService
from agentshield_console_api.app import create_app
from agentshield_console_api.policies import PolicyRegistry
from agentshield_ledger.ledger import Ledger
from agentshield_revocation.epoch_store import InMemoryEpochStore
from agentshield_revocation.kill_switch import KillSwitch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

pytestmark = pytest.mark.asyncio

SEND_EMAIL_TOOL: dict[str, Any] = {
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
    principal,
    action == AgentShield::Action::"send_email",
    resource
) when { context.input.to == "alice@example.com" };
"""

ALLOW_ANYONE = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
);
"""


def _build(**app_overrides: Any) -> tuple[httpx.AsyncClient, Ledger, ApprovalService, KillSwitch]:
    registry = PolicyRegistry()
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    key = Ed25519PrivateKey.generate()
    approvals = ApprovalService(
        signing_key=key,
        public_key_hex=key.public_key().public_bytes_raw().hex(),
        queue=InMemoryPendingApprovalQueue(),
        nonce_store=InMemoryNonceStore(),
        receipt_ttl_seconds=120.0,
    )
    kill_switch = KillSwitch(
        epoch_store=InMemoryEpochStore(), approval_drain=approvals, ledger=ledger
    )
    app = create_app(
        policy_registry=registry,
        approval_service=approvals,
        ledger=ledger,
        kill_switch=kill_switch,
        **app_overrides,
    )
    transport = httpx.ASGITransport(app=app)
    client = httpx.AsyncClient(transport=transport, base_url="http://console.test")
    return client, ledger, approvals, kill_switch


async def test_healthz() -> None:
    client, _, _, _ = _build()
    async with client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


async def test_register_then_get_policy() -> None:
    client, _, _, _ = _build()
    async with client:
        created = await client.post(
            "/sessions/s1/policy",
            json={"tools": [SEND_EMAIL_TOOL], "policy_text": ALLOW_ALICE_ONLY},
        )
        assert created.status_code == 201
        assert created.json() == {"session_id": "s1", "policy_text": ALLOW_ALICE_ONLY}

        fetched = await client.get("/sessions/s1/policy")
        assert fetched.status_code == 200
        assert fetched.json()["policy_text"] == ALLOW_ALICE_ONLY


async def test_get_policy_for_unknown_session_is_404() -> None:
    client, _, _, _ = _build()
    async with client:
        response = await client.get("/sessions/no-such-session/policy")
        assert response.status_code == 404


async def test_register_with_a_malformed_policy_is_400() -> None:
    client, _, _, _ = _build()
    async with client:
        response = await client.post(
            "/sessions/s1/policy",
            json={"tools": [SEND_EMAIL_TOOL], "policy_text": "not cedar {{{"},
        )
        assert response.status_code == 400


async def test_validate_endpoint_reports_valid_and_invalid_candidates() -> None:
    client, _, _, _ = _build()
    async with client:
        await client.post(
            "/sessions/s1/policy",
            json={"tools": [SEND_EMAIL_TOOL], "policy_text": ALLOW_ALICE_ONLY},
        )
        ok = await client.post("/sessions/s1/policy/validate", json={"policy_text": ALLOW_ANYONE})
        assert ok.status_code == 200
        assert ok.json() == {"valid": True, "errors": []}

        bad = await client.post(
            "/sessions/s1/policy/validate", json={"policy_text": "not cedar {{{"}
        )
        assert bad.status_code == 200
        body = bad.json()
        assert body["valid"] is False
        assert body["errors"]


async def test_propose_update_endpoint_auto_applies_a_narrowing_and_blocks_an_expansion() -> None:
    client, _, _, _ = _build()
    async with client:
        await client.post(
            "/sessions/s1/policy",
            json={"tools": [SEND_EMAIL_TOOL], "policy_text": ALLOW_ALICE_ONLY},
        )

        narrower = """
        permit(
            principal,
            action == AgentShield::Action::"send_email",
            resource
        ) when {
            context.input.to == "alice@example.com" && context.input.body == "hi"
        };
        """
        narrowing = await client.put("/sessions/s1/policy", json={"policy_text": narrower})
        assert narrowing.status_code == 200
        body = narrowing.json()
        assert body["decision"] == "ALLOW"
        assert body["applied"] is True
        assert body["subsumption_report"] is None

        expansion = await client.put("/sessions/s1/policy", json={"policy_text": ALLOW_ANYONE})
        assert expansion.status_code == 200
        body = expansion.json()
        assert body["decision"] == "REQUIRE_APPROVAL"
        assert body["applied"] is False
        assert body["subsumption_report"] is not None
        assert body["subsumption_report"]["outcome"] in {"EXPANSION", "UNPROVEN"}

        # Confirm the registry really did reject the expansion.
        current = await client.get("/sessions/s1/policy")
        assert current.json()["policy_text"].strip() == narrower.strip()


async def test_full_approval_lifecycle_through_the_http_api() -> None:
    client, ledger, approvals, _ = _build()
    async with client:
        pending = await approvals.request_approval(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "mallory@example.com"},
            resource_version=0,
        )

        listed = await client.get("/approvals")
        assert listed.status_code == 200
        [entry] = listed.json()
        assert entry["request_id"] == pending.request_id
        assert entry["arguments"] == {"to": "mallory@example.com"}

        approved = await client.post(
            f"/approvals/{pending.request_id}/approve", json={"nonce": "n1"}
        )
        assert approved.status_code == 200
        receipt_body = approved.json()
        assert receipt_body["payload"]["session_id"] == "s1"
        assert "signature" in receipt_body

        listed_after = await client.get("/approvals")
        assert listed_after.json() == []


async def test_denying_an_approval_through_the_http_api() -> None:
    client, _, approvals, _ = _build()
    async with client:
        pending = await approvals.request_approval(
            session_id="s1", tool_name="t", arguments={}, resource_version=0
        )
        response = await client.post(f"/approvals/{pending.request_id}/deny")
        assert response.status_code == 200
        assert response.json()["status"] == "denied"


async def test_approving_an_unknown_request_is_404() -> None:
    client, _, _, _ = _build()
    async with client:
        response = await client.post("/approvals/does-not-exist/approve", json={"nonce": "n1"})
        assert response.status_code == 404


async def test_approving_an_already_resolved_request_is_409() -> None:
    client, _, approvals, _ = _build()
    async with client:
        pending = await approvals.request_approval(
            session_id="s1", tool_name="t", arguments={}, resource_version=0
        )
        await client.post(f"/approvals/{pending.request_id}/approve", json={"nonce": "n1"})
        again = await client.post(f"/approvals/{pending.request_id}/approve", json={"nonce": "n2"})
        assert again.status_code == 409


async def test_approval_stream_emits_an_initial_snapshot_event() -> None:
    # `httpx.ASGITransport` drives the ASGI app's `__call__` to full
    # completion before it ever returns a response, so a genuinely
    # unbounded stream cannot be observed this way at all (see
    # `create_app`'s own docstring on `approval_stream_max_iterations`).
    # Bounding the stream to a handful of iterations with no poll delay
    # lets the ASGI call actually finish within the test, while still
    # exercising the real `StreamingResponse` wiring end to end.
    client, _, approvals, _ = _build(
        approval_stream_max_iterations=2, approval_stream_poll_interval_seconds=0.0
    )
    async with client:
        await approvals.request_approval(
            session_id="s1", tool_name="t", arguments={"x": 1}, resource_version=0
        )
        response = await client.get("/approvals/stream")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert "event: snapshot" in response.text
        assert '"x": 1' in response.text


async def test_audit_explorer_lists_a_sessions_entries_and_reports_chain_integrity() -> None:
    client, ledger, _, _ = _build()
    async with client:
        ledger.append(
            "decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"}
        )
        ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
        ledger.append("decision", {"session_id": "s2", "decision": "DENY", "stage": "principal"})

        response = await client.get("/audit/sessions/s1")
        assert response.status_code == 200
        body = response.json()
        assert body["chain_intact"] is True
        assert [e["event_type"] for e in body["entries"]] == ["decision", "tool_outcome"]


async def test_audit_explorer_surfaces_a_provenance_path_when_present() -> None:
    client, ledger, _, _ = _build()
    async with client:
        ledger.append(
            "decision",
            {
                "session_id": "s1",
                "decision": "DENY",
                "stage": "information_flow",
                "reason": "ceiling exceeded",
                "provenance_path": "value derives from 'tool:read_email#msg_42' via chain: ...",
            },
        )
        response = await client.get("/audit/sessions/s1")
        [entry] = response.json()["entries"]
        assert "msg_42" in entry["payload"]["provenance_path"]


async def test_session_replay_endpoint() -> None:
    client, ledger, _, _ = _build()
    async with client:
        ledger.append(
            "decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"}
        )
        ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})

        response = await client.get("/audit/sessions/s1/replay")
        assert response.status_code == 200
        body = response.json()
        assert body["chain_intact"] is True
        assert body["final_decision"] == "ALLOW"
        assert len(body["steps"]) == 2


async def test_global_kill_switch_bumps_epoch_and_reports_blast_radius() -> None:
    client, ledger, _, kill_switch = _build()
    async with client:
        ledger.append("tool_outcome", {"session_id": "s1", "tool": "send_email", "status": "ok"})
        response = await client.post("/kill-switch/global", json={"reason": "incident"})
        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == "global"
        assert body["new_global_epoch"] == 1
        assert len(body["blast_radius"]) == 1
        assert body["blast_radius"][0]["session_id"] == "s1"


async def test_session_kill_switch_bumps_only_that_sessions_epoch() -> None:
    client, _, _, _ = _build()
    async with client:
        response = await client.post(
            "/kill-switch/sessions/s1", json={"reason": "suspected compromise"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["scope"] == "session"
        assert body["session_id"] == "s1"
        assert body["new_session_epoch"] == 1
        assert body["new_global_epoch"] is None
