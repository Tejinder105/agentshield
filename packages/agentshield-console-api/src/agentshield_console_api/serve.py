"""Production ASGI entrypoint for the console API.

`create_app` keeps its collaborators injectable for tests and deployments.
This module supplies the in-memory implementations used by the local
single-process development server.
"""

from __future__ import annotations

from typing import Any

from agentshield_approvals.nonce_store import InMemoryNonceStore
from agentshield_approvals.queue import InMemoryPendingApprovalQueue
from agentshield_approvals.service import ApprovalService
from agentshield_console_api.app import create_app
from agentshield_console_api.policies import PolicyRegistry
from agentshield_ledger.ledger import Ledger
from agentshield_revocation.epoch_store import InMemoryEpochStore
from agentshield_revocation.kill_switch import KillSwitch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.middleware.cors import CORSMiddleware


def app() -> Any:
    """Build a development console API with in-memory collaborators."""
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    approval_key = Ed25519PrivateKey.generate()
    approval_service = ApprovalService(
        signing_key=approval_key,
        public_key_hex=approval_key.public_key().public_bytes_raw().hex(),
        queue=InMemoryPendingApprovalQueue(),
        nonce_store=InMemoryNonceStore(),
    )
    application = create_app(
        policy_registry=PolicyRegistry(),
        approval_service=approval_service,
        ledger=ledger,
        kill_switch=KillSwitch(
            epoch_store=InMemoryEpochStore(),
            approval_drain=approval_service,
            ledger=ledger,
        ),
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return application
