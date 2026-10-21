"""GenAI semantic convention attribute keys this package uses, plus Agent
Shield's own `agent_shield.*` namespaced attributes for policy-decision
detail the GenAI conventions have no slot for.

Keys are kept as local string constants rather than imported from
`opentelemetry.semconv`: that package's GenAI conventions are still
experimental/incubating upstream, and relying on it would make this
module's exact import path hostage to a future upstream rename. Pinning
the handful of keys actually used here means this package controls its
own compatibility surface.
"""

from __future__ import annotations

# --- GenAI semantic conventions (https://opentelemetry.io/docs/specs/semconv/gen-ai/) ---
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"

# --- GenAI operation names this package produces spans for ---
OPERATION_INVOKE_AGENT = "invoke_agent"
OPERATION_EXECUTE_TOOL = "execute_tool"

# --- Agent Shield's own attributes: no GenAI convention covers "why did
# the policy engine decide this", so these are namespaced under
# `agent_shield.*` rather than invented under `gen_ai.*`. ---
AGENT_SHIELD_DECISION_KIND = "agent_shield.decision.kind"
AGENT_SHIELD_DECISION_STAGE = "agent_shield.decision.stage"
AGENT_SHIELD_DECISION_REASON = "agent_shield.decision.reason"
AGENT_SHIELD_OUTCOME_STATUS = "agent_shield.outcome.status"
AGENT_SHIELD_ENFORCED = "agent_shield.enforced"
AGENT_SHIELD_ENFORCEMENT_MODE = "agent_shield.enforcement.mode"

# --- Span event names ---
EVENT_POLICY_DECISION = "agent_shield.policy_decision"
EVENT_SHADOW_DISPATCH_ATTEMPTED = "agent_shield.shadow_dispatch_attempted"
EVENT_SHADOW_DISPATCH_SUCCEEDED = "agent_shield.shadow_dispatch_succeeded"
EVENT_SHADOW_DISPATCH_FAILED = "agent_shield.shadow_dispatch_failed"
