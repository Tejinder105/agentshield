from __future__ import annotations

from agentshield_approvals.tiering import ConsequenceTieringPolicy
from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaLeg
from agentshield_eval.ablation import (
    ABLATION_CONFIGS,
    ApprovalReviewer,
    PillarFlags,
    _AlwaysApproveReceiptVerifier,
    ablate_policy_text,
    ablate_tool_classes,
    ablation_variant,
    build_ablation_boundaries,
)
from agentshield_eval.tool_profiles import ToolSecurityClass
from agentshield_gateway.boundaries import NeverRequiresApproval, RejectAllReceiptVerifier
from agentshield_gateway.registry import ToolSecurityProfile


def _sample_tool_classes() -> dict[str, ToolSecurityClass]:
    return {
        "read": ToolSecurityClass(
            profile=ToolSecurityProfile(
                ceiling=Label.top(), trifecta_leg=TrifectaLeg.UNTRUSTED_INPUT
            ),
            read_label=Label.untrusted(),
        ),
        "send": ToolSecurityClass(
            profile=ToolSecurityProfile(
                ceiling=Label.bottom(), trifecta_leg=TrifectaLeg.EXTERNAL_COMMUNICATION
            ),
        ),
    }


def test_full_config_leaves_tool_classes_unchanged() -> None:
    classes = _sample_tool_classes()
    adjusted = ablate_tool_classes(classes, PillarFlags())
    assert adjusted == classes
    assert adjusted is not classes


def test_no_label_lattice_widens_every_ceiling_and_zeroes_read_labels() -> None:
    classes = _sample_tool_classes()
    adjusted = ablate_tool_classes(classes, PillarFlags(label_lattice=False))
    for tool_class in adjusted.values():
        assert tool_class.profile.ceiling == Label.top()
        assert tool_class.read_label == Label.bottom()
    # trifecta legs are untouched by this specific axis
    assert adjusted["read"].profile.trifecta_leg is TrifectaLeg.UNTRUSTED_INPUT


def test_no_trifecta_clears_every_leg_but_keeps_ceilings() -> None:
    classes = _sample_tool_classes()
    adjusted = ablate_tool_classes(classes, PillarFlags(trifecta=False))
    for tool_class in adjusted.values():
        assert tool_class.profile.trifecta_leg is None
    assert adjusted["send"].profile.ceiling == Label.bottom()


def test_ablate_policy_text_swaps_in_permit_all_when_cedar_is_off() -> None:
    original = "permit(principal, action, resource) when { false };"
    assert ablate_policy_text(original, PillarFlags()) == original
    assert (
        ablate_policy_text(
            "permit(principal, action, resource) when { false };", PillarFlags(cedar_policy=False)
        )
        == "permit(principal, action, resource);"
    )


def test_approval_tiering_off_disables_approvals_entirely() -> None:
    policy, verifier = build_ablation_boundaries(
        _sample_tool_classes(), PillarFlags(approval_tiering=ApprovalReviewer.OFF)
    )
    assert isinstance(policy, NeverRequiresApproval)
    assert isinstance(verifier, _AlwaysApproveReceiptVerifier)


def test_approval_tiering_responsive_tiers_egress_tools_and_always_approves() -> None:
    policy, verifier = build_ablation_boundaries(
        _sample_tool_classes(), PillarFlags(approval_tiering=ApprovalReviewer.RESPONSIVE)
    )
    assert isinstance(policy, ConsequenceTieringPolicy)
    assert policy.requires_approval("send", {})
    assert not policy.requires_approval("read", {})
    assert isinstance(verifier, _AlwaysApproveReceiptVerifier)


def test_approval_tiering_unresponsive_tiers_egress_tools_and_never_approves() -> None:
    policy, verifier = build_ablation_boundaries(
        _sample_tool_classes(), PillarFlags(approval_tiering=ApprovalReviewer.UNRESPONSIVE)
    )
    assert isinstance(policy, ConsequenceTieringPolicy)
    assert policy.requires_approval("send", {})
    assert isinstance(verifier, RejectAllReceiptVerifier)


def test_ablation_configs_cover_every_pillar_once() -> None:
    assert set(ABLATION_CONFIGS) == {
        "full",
        "no_cedar_policy",
        "no_label_lattice",
        "no_trifecta",
        "no_approval_tiering",
        "unresponsive_approval_reviewer",
    }


def test_ablation_variant_wires_classes_and_boundaries_together() -> None:
    classes, policy, verifier = ablation_variant(
        _sample_tool_classes(), ABLATION_CONFIGS["no_trifecta"]
    )
    assert all(tc.profile.trifecta_leg is None for tc in classes.values())
    assert isinstance(policy, ConsequenceTieringPolicy)  # default responsive reviewer still applies
    assert isinstance(verifier, _AlwaysApproveReceiptVerifier)
