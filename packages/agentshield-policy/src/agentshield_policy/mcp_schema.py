"""Generate a Cedar schema from an MCP server's `tools/list` response.

Agent Shield pins one Cedar action per MCP tool, with the tool's declared
JSON Schema mapped into that action's context under the `input` key. This
gives Cedar policies argument-level granularity -- "permit send_email only
when context.input.to is in this allowlist" -- rather than coarse,
tool-level allow/deny.

The same tool-list digest computed here is reused by the gateway for
tool-schema pinning: if an MCP server silently changes a tool's advertised
schema or description mid-session, the digest changes and the gateway
treats that as a supply-chain "rug pull", not a benign update.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import cedar_mcp_schema_generator as _gen

DEFAULT_NAMESPACE = "AgentShield"


class SchemaGenerationError(RuntimeError):
    """Raised when the Cedar schema cannot be generated from the tool list."""


def _default_schema_stub(namespace: str) -> str:
    return f"""
namespace {namespace} {{
  @mcp_principal
  entity Session {{}};

  @mcp_resource
  entity Tool {{}};
}}
"""


def _cedar_string_literal(value: str) -> str:
    """Escape a Python string as a Cedar string literal."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def digest_tools(tools: list[dict[str, Any]]) -> str:
    """A stable SHA-256 digest over an MCP `tools/list` response.

    Used both to generate the Cedar schema here and, independently, by the
    gateway to detect a server that changes its advertised tools
    mid-session.
    """
    canonical = json.dumps(tools, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class GeneratedSchema:
    """A Cedar schema generated from one MCP server's tool descriptions,
    together with the exact tool-list digest it was built from.
    """

    namespace: str
    schema_text: str  # .cedarschema human-readable form
    schema_json: dict[str, Any]  # JSON form, consumable by cedarpy.validate_policies
    tools_digest: str

    def entity_uid(self, entity_type: str, entity_id: str) -> str:
        """Render a Cedar entity UID literal, e.g. AgentShield::Session::"s1"."""
        return f"{self.namespace}::{entity_type}::{_cedar_string_literal(entity_id)}"

    def action_uid(self, tool_name: str) -> str:
        return f"{self.namespace}::Action::{_cedar_string_literal(tool_name)}"


def generate_schema(
    tools: list[dict[str, Any]],
    *,
    namespace: str = DEFAULT_NAMESPACE,
    schema_stub: str | None = None,
) -> GeneratedSchema:
    """Generate a Cedar schema from an MCP `tools/list` response.

    One Cedar action is produced per tool (named after the tool), applying
    to a `Session` principal and a `Tool` resource, with the tool's JSON
    Schema folded into the action's `input` context attribute.
    """
    stub = schema_stub if schema_stub is not None else _default_schema_stub(namespace)
    try:
        result = _gen.generate_schema_or_raise(stub, tools)
    except _gen.SchemaGeneratorError as exc:
        raise SchemaGenerationError(f"failed to generate Cedar schema: {exc}") from exc

    return GeneratedSchema(
        namespace=namespace,
        schema_text=result["schema"],
        schema_json=json.loads(result["schemaJson"]),
        tools_digest=digest_tools(tools),
    )
