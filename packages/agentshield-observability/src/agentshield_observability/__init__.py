"""OpenTelemetry instrumentation for the gateway's decision pipeline,
using the GenAI semantic conventions, plus a shadow/log-only enforcement
mode so a team can see what *would* be blocked before turning enforcement
on.
"""

from agentshield_observability.pipeline import (
    EnforcementMode,
    InstrumentedDecisionPipeline,
    ObservedOutcome,
    Pipeline,
)
from agentshield_observability.spans import (
    decision_attributes,
    execute_tool_span,
    invoke_agent_span,
    record_decision,
    record_outcome,
)

__all__ = [
    "EnforcementMode",
    "InstrumentedDecisionPipeline",
    "ObservedOutcome",
    "Pipeline",
    "decision_attributes",
    "execute_tool_span",
    "invoke_agent_span",
    "record_decision",
    "record_outcome",
]
