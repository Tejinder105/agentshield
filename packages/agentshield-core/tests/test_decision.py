from __future__ import annotations

from agentshield_core.decision import Decision, DecisionKind, most_severe


def test_constructors_set_the_right_kind() -> None:
    assert Decision.allow("ok", stage="cedar").kind is DecisionKind.ALLOW
    assert Decision.deny("blocked", stage="cedar").kind is DecisionKind.DENY
    approval = Decision.require_approval("needs human", stage="label")
    assert approval.kind is DecisionKind.REQUIRE_APPROVAL


def test_convenience_properties() -> None:
    allow = Decision.allow("ok", stage="cedar")
    deny = Decision.deny("blocked", stage="cedar")
    approval = Decision.require_approval("needs human", stage="label")

    assert allow.is_allowed and not allow.is_denied and not allow.needs_approval
    assert deny.is_denied and not deny.is_allowed and not deny.needs_approval
    assert approval.needs_approval and not approval.is_allowed and not approval.is_denied


def test_most_severe_deny_wins_over_everything() -> None:
    allow = Decision.allow("ok", stage="s1")
    approval = Decision.require_approval("needs human", stage="s2")
    deny = Decision.deny("blocked", stage="s3")

    assert most_severe((allow, approval, deny)).kind is DecisionKind.DENY
    assert most_severe((deny, allow, approval)).kind is DecisionKind.DENY


def test_most_severe_approval_beats_allow() -> None:
    allow = Decision.allow("ok", stage="s1")
    approval = Decision.require_approval("needs human", stage="s2")
    assert most_severe((allow, approval)).kind is DecisionKind.REQUIRE_APPROVAL


def test_most_severe_empty_defaults_to_deny() -> None:
    """Fail-closed: with no stages evaluated at all, the pipeline must not
    default to allow.
    """
    assert most_severe(()).kind is DecisionKind.DENY
