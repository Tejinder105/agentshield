from __future__ import annotations

from agentshield_approvals.tiering import ApprovalTier, ConsequenceTieringPolicy


def test_default_tier_is_none_for_unregistered_tools() -> None:
    policy = ConsequenceTieringPolicy()
    assert policy.tier_for("send_email", {}) is ApprovalTier.NONE
    assert policy.requires_approval("send_email", {}) is False


def test_unconditional_rule_applies_to_every_call() -> None:
    policy = ConsequenceTieringPolicy()
    policy.register("delete_account", ApprovalTier.HIGH)
    assert policy.tier_for("delete_account", {"id": 1}) is ApprovalTier.HIGH
    assert policy.requires_approval("delete_account", {"id": 1}) is True


def test_conditional_rule_only_applies_when_predicate_matches() -> None:
    policy = ConsequenceTieringPolicy()
    policy.register(
        "transfer_funds", ApprovalTier.HIGH, when=lambda args: args.get("amount_usd", 0) > 1000
    )
    assert policy.tier_for("transfer_funds", {"amount_usd": 50}) is ApprovalTier.NONE
    assert policy.tier_for("transfer_funds", {"amount_usd": 5000}) is ApprovalTier.HIGH


def test_first_matching_rule_wins_in_registration_order() -> None:
    policy = ConsequenceTieringPolicy()
    policy.register(
        "transfer_funds", ApprovalTier.LOW, when=lambda args: args.get("amount_usd", 0) <= 1000
    )
    policy.register("transfer_funds", ApprovalTier.HIGH)  # unconditional fallback
    assert policy.tier_for("transfer_funds", {"amount_usd": 50}) is ApprovalTier.LOW
    assert policy.tier_for("transfer_funds", {"amount_usd": 50000}) is ApprovalTier.HIGH


def test_default_tier_can_be_overridden_to_require_approval_by_default() -> None:
    policy = ConsequenceTieringPolicy(default_tier=ApprovalTier.LOW)
    assert policy.requires_approval("any_unregistered_tool", {}) is True
