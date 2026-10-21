"""Production ASGI entrypoint.

`create_app` takes its collaborators as arguments so tests can inject
fakes; a container has no such caller. This module is the one place a
deployment is allowed to construct those collaborators from the
environment, and it fails closed: missing configuration produces a
deny-all Cedar policy and an empty tool registry, never a permit-all
gateway that started "to be helpful".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentshield_gateway.app import create_app
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.egress import EgressPolicy
from agentshield_gateway.pipeline import DecisionPipeline
from agentshield_gateway.registry import ToolRegistry
from agentshield_gateway.session import SessionStore


def _policy_text() -> str:
    path = os.environ.get("AGENTSHIELD_POLICY_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8")
    return os.environ.get(
        "AGENTSHIELD_POLICY_TEXT",
        "// no policy configured: default-deny\n",
    )


def _allowed_hosts() -> frozenset[str] | None:
    raw = os.environ.get("AGENTSHIELD_EGRESS_ALLOWED_HOSTS")
    if raw is None:
        return None
    hosts = frozenset(part.strip() for part in raw.split(",") if part.strip())
    return hosts


def build_pipeline() -> DecisionPipeline:
    tools: list[dict[str, Any]] = []
    schema = generate_schema(tools) if tools else generate_schema([])
    store = PolicyStore(policy_text=_policy_text(), schema=schema)
    pdp = PolicyDecisionPoint(schema, store)
    registry = ToolRegistry()
    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    return DecisionPipeline(
        policy_decision_point=pdp,
        ledger=ledger,
        tool_registry=registry,
        egress_policy=EgressPolicy(allowed_hosts=_allowed_hosts()),
    )


def app() -> Any:
    return create_app(
        pipeline=build_pipeline(),
        sessions=SessionStore(),
        dispatcher=InMemoryToolDispatcher(),
    )
