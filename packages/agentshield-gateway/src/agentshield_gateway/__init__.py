"""Agent Shield gateway: the Policy Enforcement Point for agents whose
code you do not control.

Where `agentshield-sdk` gives per-value label propagation inside a trusted
agent process, the gateway sits in front of an MCP server and enforces the
same fixed, fail-closed decision pipeline from the outside, by intercepting
`tools/call`.
"""

from agentshield_gateway.dispatch import InMemoryToolDispatcher, ToolDispatcher
from agentshield_gateway.egress import EgressPolicy
from agentshield_gateway.pipeline import (
    DecisionPipeline,
    GatewayOutcome,
    OutcomeStatus,
    ToolCallRequest,
)
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.schema_pinning import PinnedToolSet, digest_tool
from agentshield_gateway.session import GatewaySession, SessionStore

__all__ = [
    "DecisionPipeline",
    "GatewayOutcome",
    "OutcomeStatus",
    "ToolCallRequest",
    "PinnedToolSet",
    "digest_tool",
    "GatewaySession",
    "SessionStore",
    "ToolDispatcher",
    "InMemoryToolDispatcher",
    "ToolRegistry",
    "ToolSecurityProfile",
    "EgressPolicy",
]
