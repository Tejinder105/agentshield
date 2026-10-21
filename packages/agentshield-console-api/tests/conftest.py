from __future__ import annotations

from typing import Any

import pytest
from agentshield_approvals.nonce_store import InMemoryNonceStore
from agentshield_approvals.queue import InMemoryPendingApprovalQueue
from agentshield_approvals.service import ApprovalService
from agentshield_console_api.policies import PolicyRegistry
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema
from agentshield_revocation.epoch_store import InMemoryEpochStore
from agentshield_revocation.kill_switch import KillSwitch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


@pytest.fixture
def sample_schema() -> GeneratedSchema:
    return generate_schema([SEND_EMAIL_TOOL])


@pytest.fixture
def policy_registry(sample_schema: GeneratedSchema) -> PolicyRegistry:
    registry = PolicyRegistry()
    registry.register("s1", schema=sample_schema, policy_text=ALLOW_ALICE_ONLY)
    return registry


@pytest.fixture
def ledger() -> Ledger:
    return Ledger(signing_key=Ed25519PrivateKey.generate())


@pytest.fixture
def approval_service() -> ApprovalService:
    key = Ed25519PrivateKey.generate()
    return ApprovalService(
        signing_key=key,
        public_key_hex=key.public_key().public_bytes_raw().hex(),
        queue=InMemoryPendingApprovalQueue(),
        nonce_store=InMemoryNonceStore(),
        receipt_ttl_seconds=120.0,
    )


@pytest.fixture
def kill_switch(ledger: Ledger, approval_service: ApprovalService) -> KillSwitch:
    return KillSwitch(
        epoch_store=InMemoryEpochStore(), approval_drain=approval_service, ledger=ledger
    )
