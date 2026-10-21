"""Agent Shield's security evaluation harness.

See the package docstrings of `agentshield_eval.harness`,
`agentshield_eval.pipeline_element`, `agentshield_eval.metrics`,
`agentshield_eval.agentdyn`, `agentshield_eval.adaptive_attacks`, and
`agentshield_eval.ablation` for what each module covers; this module only
re-exports the handful of names most callers need.
"""

from agentshield_eval.ablation import (
    ABLATION_CONFIGS,
    ApprovalReviewer,
    PillarFlags,
    ablation_variant,
)
from agentshield_eval.agentdyn import (
    AgentDynDataset,
    AgentDynTask,
    OverDefenseResult,
    evaluate_over_defense,
    load_agentdyn_dataset,
)
from agentshield_eval.harness import (
    AgentShieldBenchmarkPipeline,
    AgentShieldHarness,
    build_agent_shield_pipeline,
    build_harness,
)
from agentshield_eval.metrics import BenchmarkMetrics, compute_metrics
from agentshield_eval.pipeline_element import AgentShieldToolsExecutor, RecordedToolCallDecision
from agentshield_eval.tool_profiles import ToolSecurityClass, profiles_for_suite

__all__ = [
    "ABLATION_CONFIGS",
    "AgentDynDataset",
    "AgentDynTask",
    "AgentShieldBenchmarkPipeline",
    "AgentShieldHarness",
    "AgentShieldToolsExecutor",
    "ApprovalReviewer",
    "BenchmarkMetrics",
    "OverDefenseResult",
    "PillarFlags",
    "RecordedToolCallDecision",
    "ToolSecurityClass",
    "ablation_variant",
    "build_agent_shield_pipeline",
    "build_harness",
    "compute_metrics",
    "evaluate_over_defense",
    "load_agentdyn_dataset",
    "profiles_for_suite",
]
