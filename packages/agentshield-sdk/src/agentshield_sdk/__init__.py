"""Agent Shield SDK: in-process middleware for agent frameworks.

Gives per-value label propagation a gateway cannot see, and implements the
dual-LLM quarantine (`var_` handles plus a tool-less, schema-constrained
parser) described in the plan's "advanced features" section.

Framework-specific adapters (`agentshield_sdk.integrations.openai_agents`,
`agentshield_sdk.integrations.langchain`) are intentionally *not*
re-exported here -- importing either requires that framework's package to
be installed (see the `openai-agents` and `langchain` extras in
`pyproject.toml`), and this top-level module must import cleanly with
neither present.
"""

from agentshield_sdk.dispatch import SdkGatewayClient, resolve_and_label
from agentshield_sdk.handles import UnknownHandleError, VarHandle, VarStore
from agentshield_sdk.quarantine import (
    DEFAULT_INSTRUCTIONS,
    SchemaConstrainedLLM,
    quarantine_parse,
)
from agentshield_sdk.session import SdkSession
from agentshield_sdk.toolwrap import quarantine_tool_output

__all__ = [
    "DEFAULT_INSTRUCTIONS",
    "SchemaConstrainedLLM",
    "SdkGatewayClient",
    "SdkSession",
    "UnknownHandleError",
    "VarHandle",
    "VarStore",
    "quarantine_parse",
    "quarantine_tool_output",
    "resolve_and_label",
]
