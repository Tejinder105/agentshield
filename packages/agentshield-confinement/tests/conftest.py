from __future__ import annotations

import pytest
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema

SEND_EMAIL_TOOL: dict[str, object] = {
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

TRANSFER_FUNDS_TOOL: dict[str, object] = {
    "name": "transfer_funds",
    "description": "Transfer money between accounts",
    "inputSchema": {
        "type": "object",
        "properties": {
            "to_account": {"type": "string"},
            "amount_usd": {"type": "integer"},
        },
        "required": ["to_account", "amount_usd"],
    },
}


@pytest.fixture
def sample_tools() -> list[dict[str, object]]:
    return [SEND_EMAIL_TOOL, TRANSFER_FUNDS_TOOL]


@pytest.fixture
def sample_schema(sample_tools: list[dict[str, object]]) -> GeneratedSchema:
    return generate_schema(sample_tools)
