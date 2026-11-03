"""The fail-closed Policy Decision Point.

No LLM participates in this module. Every public method here is
deterministic and converts any internal failure -- a malformed request, an
exception from the Cedar engine, anything unexpected -- into
`Decision.deny`. There is no code path in this file that can turn an error
into an allow; that is the fail-closed invariant from
`docs/threat-model.md` made concrete.
"""

from __future__ import annotations

from typing import Any

import cedarpy
from agentshield_core.decision import Decision

from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.policies import PolicyStore

STAGE = "cedar_policy"


class PolicyDecisionPoint:
    """Evaluates one proposed tool call against a session's cached Cedar
    policy set.
    """

    def __init__(self, schema: GeneratedSchema, policy_store: PolicyStore) -> None:
        self._schema = schema
        self._policy_store = policy_store
        self._registered_tools: dict[str, dict[str, Any]] = {}

    def register_tools(self, tools: list[dict[str, Any]], policy_text: str | None = None) -> None:
        """Dynamically add tools into the Cedar schema and policy store."""
        from agentshield_policy.mcp_schema import generate_schema

        for t in tools:
            name = t.get("name")
            if name:
                self._registered_tools[name] = t

        new_schema = generate_schema(list(self._registered_tools.values()))
        if policy_text is None:
            existing_text = self._policy_store.policy_text
            if existing_text and not existing_text.strip().startswith("// no policy configured"):
                policy_text = existing_text
            else:
                policy_text = """
                permit(
                    principal,
                    action,
                    resource
                ) unless {
                    context.input has path && (
                        context.input.path like "*.env*" ||
                        context.input.path like "*id_rsa*" ||
                        context.input.path like "*.git/*" ||
                        context.input.path like "*credentials*"
                    )
                };
                """
        self._schema = new_schema
        self._policy_store = PolicyStore(policy_text=policy_text, schema=new_schema)

    def authorize(self, *, session_id: str, tool_name: str, arguments: dict[str, Any]) -> Decision:
        """Evaluate a single proposed tool call.

        Always returns a `Decision`; never raises. Any failure anywhere in
        this method resolves to `Decision.deny`.
        """
        try:
            request = {
                "principal": self._schema.entity_uid("Session", session_id),
                "action": self._schema.action_uid(tool_name),
                "resource": self._schema.entity_uid("Tool", tool_name),
                "context": {"input": arguments},
            }
            result = cedarpy.is_authorized(request, self._policy_store.policy_set, [])
        except Exception as exc:  # fail-closed: any engine error denies, never allows
            return Decision.deny(f"policy engine error, failing closed: {exc}", stage=STAGE)

        if result.decision is cedarpy.Decision.Allow:
            return Decision.allow(f"permitted by Cedar policy for tool {tool_name!r}", stage=STAGE)
        return Decision.deny(
            f"no Cedar policy permits tool {tool_name!r} with these arguments", stage=STAGE
        )
