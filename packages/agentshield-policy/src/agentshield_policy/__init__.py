"""Agent Shield policy engine: Cedar schema generation from MCP tool
descriptions, policy loading/validation, a fail-closed PDP, and formal
subsumption checking for monotonic confinement.
"""

from agentshield_policy.mcp_schema import GeneratedSchema, SchemaGenerationError, generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore, PolicyValidationError
from agentshield_policy.subsumption import (
    ActionSubsumptionResult,
    SubsumptionOutcome,
    SubsumptionReport,
    UnsupportedConditionError,
    check_subsumption,
)

__all__ = [
    "GeneratedSchema",
    "SchemaGenerationError",
    "generate_schema",
    "PolicyDecisionPoint",
    "PolicyStore",
    "PolicyValidationError",
    "ActionSubsumptionResult",
    "SubsumptionOutcome",
    "SubsumptionReport",
    "UnsupportedConditionError",
    "check_subsumption",
]
