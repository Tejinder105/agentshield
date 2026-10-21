"""Per-pillar ablation: measure the marginal contribution of each of
Agent Shield's pluggable enforcement boundaries by selectively
neutralizing one at a time and re-running the same benchmark.

`agentshield_gateway.pipeline.DecisionPipeline` always runs its eight
steps in the same fixed order -- that is the point of a reference
monitor, and this module does not patch around it. What it *does* vary
is the configuration handed to each step's pluggable boundary (see
`agentshield_gateway.boundaries`/`agentshield_gateway.registry`):

- `cedar_policy` off -> the Cedar policy text is replaced with a
  permit-all rule, so step 4 never denies on its own (approval tiering,
  if enabled, still can).
- `label_lattice` off -> every tool's ceiling is widened to `Label.top()`
  and every read label is reset to `Label.bottom()`, so step 5 can never
  deny.
- `trifecta` off -> every tool's trifecta leg is cleared, so step 6 can
  never deny.
- `approval_tiering` -- not a boolean, because the two "on" states tell
  materially different stories: a tiering policy that is always granted
  (`ApprovalReviewer.RESPONSIVE`, simulating an on-call reviewer who
  always eventually approves) measures the receipt-binding overhead with
  none of the utility cost; a tiering policy that is never granted
  (`ApprovalReviewer.UNRESPONSIVE`, the gateway's own fail-closed
  default in the absence of a real reviewer) measures the opposite
  extreme the plan's "human approval fatigue" risk warns about. `OFF`
  disables tiering (and schema pinning and capability checks are never
  varied here -- see the module docstring note in
  `agentshield_eval.harness` about which pillars this benchmark can and
  cannot exercise).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agentshield_approvals.tiering import ApprovalTier, ConsequenceTieringPolicy
from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_gateway.boundaries import (
    ApprovalPolicy,
    NeverRequiresApproval,
    ReceiptVerifier,
    RejectAllReceiptVerifier,
)
from agentshield_gateway.registry import ToolSecurityProfile

from agentshield_eval.tool_profiles import ToolSecurityClass

#: Cedar text that permits every action unconditionally -- the "Cedar
#: policy engine is not present" baseline for the `cedar_policy` ablation
#: axis.
PERMIT_ALL_POLICY = "permit(principal, action, resource);"


class ApprovalReviewer(StrEnum):
    OFF = "off"
    RESPONSIVE = "responsive"
    UNRESPONSIVE = "unresponsive"


@dataclass(frozen=True, slots=True)
class PillarFlags:
    cedar_policy: bool = True
    label_lattice: bool = True
    trifecta: bool = True
    approval_tiering: ApprovalReviewer = ApprovalReviewer.RESPONSIVE


#: The configurations `run_ablation` reports, in the order the plan asks
#: for: the fully-enabled baseline, then each pillar neutralized once.
ABLATION_CONFIGS: dict[str, PillarFlags] = {
    "full": PillarFlags(),
    "no_cedar_policy": PillarFlags(cedar_policy=False),
    "no_label_lattice": PillarFlags(label_lattice=False),
    "no_trifecta": PillarFlags(trifecta=False),
    "no_approval_tiering": PillarFlags(approval_tiering=ApprovalReviewer.OFF),
    "unresponsive_approval_reviewer": PillarFlags(approval_tiering=ApprovalReviewer.UNRESPONSIVE),
}


def ablate_policy_text(policy_text: str, flags: PillarFlags) -> str:
    return policy_text if flags.cedar_policy else PERMIT_ALL_POLICY


def ablate_tool_classes(
    tool_classes: dict[str, ToolSecurityClass], flags: PillarFlags
) -> dict[str, ToolSecurityClass]:
    """Returns a new classification map with the `label_lattice`/
    `trifecta` pillars neutralized at their only configurable input --
    never mutates `tool_classes` itself.
    """
    if flags.label_lattice and flags.trifecta:
        return dict(tool_classes)
    adjusted: dict[str, ToolSecurityClass] = {}
    for name, tool_class in tool_classes.items():
        ceiling = tool_class.profile.ceiling if flags.label_lattice else Label.top()
        leg: TrifectaLeg | None = tool_class.profile.trifecta_leg if flags.trifecta else None
        read_label = tool_class.read_label if flags.label_lattice else Label.bottom()
        adjusted[name] = ToolSecurityClass(
            profile=ToolSecurityProfile(ceiling=ceiling, trifecta_leg=leg), read_label=read_label
        )
    return adjusted


class _AlwaysApproveReceiptVerifier:
    """Simulates a responsive human reviewer for ablation purposes: every
    receipt presented is treated as valid. This is a benchmark-only
    stand-in, never a substitute for `agentshield_approvals.service.
    ApprovalService.verify` -- the real Ed25519 receipt binding is
    exercised by that package's own test suite, not here. This class
    only exists to let `run_ablation` measure the *utility* cost of
    tiering independent of whether a reviewer actually shows up.
    """

    async def verify(
        self,
        receipt: Any,  # noqa: ARG002
        *,
        session_id: str,  # noqa: ARG002
        tool_name: str,  # noqa: ARG002
        arguments: Any,  # noqa: ARG002
    ) -> bool:
        return True


def build_ablation_boundaries(
    tool_classes: dict[str, ToolSecurityClass], flags: PillarFlags
) -> tuple[ApprovalPolicy, ReceiptVerifier]:
    """The `(approval_policy, receipt_verifier)` pair to hand to
    `DecisionPipeline` for `flags.approval_tiering`. Every
    `EXTERNAL_COMMUNICATION`-leg tool (the egress sinks -- see
    `agentshield_eval.tool_profiles`) is tiered `HIGH`; everything else
    stays `NONE` regardless of reviewer responsiveness, since tiering an
    informational read would only measure approval fatigue, not egress
    risk.
    """
    if flags.approval_tiering is ApprovalReviewer.OFF:
        return NeverRequiresApproval(), _AlwaysApproveReceiptVerifier()

    tiering = ConsequenceTieringPolicy()
    for name, tool_class in tool_classes.items():
        if tool_class.profile.trifecta_leg is TrifectaLeg.EXTERNAL_COMMUNICATION:
            tiering.register(name, ApprovalTier.HIGH)

    if flags.approval_tiering is ApprovalReviewer.RESPONSIVE:
        return tiering, _AlwaysApproveReceiptVerifier()

    # UNRESPONSIVE: tiering is in effect, but nothing is ever approved --
    # the gateway's own fail-closed default verifier.
    return tiering, RejectAllReceiptVerifier()


def ablation_variant(
    tool_classes: dict[str, ToolSecurityClass], flags: PillarFlags
) -> tuple[dict[str, ToolSecurityClass], ApprovalPolicy, ReceiptVerifier]:
    """Everything `agentshield_eval.harness.build_harness` needs to build
    one ablation configuration's pipeline: the neutralized tool-class
    map, and the approval boundary pair for this `flags.approval_tiering`
    state.
    """
    adjusted = ablate_tool_classes(tool_classes, flags)
    approval_policy, receipt_verifier = build_ablation_boundaries(adjusted, flags)
    return adjusted, approval_policy, receipt_verifier
