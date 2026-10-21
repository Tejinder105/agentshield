"""Monotonic confinement: an LLM-synthesized initial Cedar policy at
session start (`agentshield_confinement.synthesis`), plus a subsumption-
gated update path where only policy changes *proven* to narrow the
session's current action space auto-apply -- everything else requires
human approval (`agentshield_confinement.gate`).
"""

from agentshield_confinement.gate import propose_policy_update
from agentshield_confinement.synthesis import (
    DEFAULT_DENY_ALL_POLICY,
    PolicySynthesizer,
    SynthesisResult,
    synthesize_initial_policy,
)

__all__ = [
    "propose_policy_update",
    "DEFAULT_DENY_ALL_POLICY",
    "PolicySynthesizer",
    "SynthesisResult",
    "synthesize_initial_policy",
]
