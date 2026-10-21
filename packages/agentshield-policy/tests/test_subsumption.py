from __future__ import annotations

import pytest
from agentshield_policy.mcp_schema import GeneratedSchema, generate_schema
from agentshield_policy.subsumption import SubsumptionOutcome, check_subsumption

UNCONDITIONAL_SEND_EMAIL = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
);
"""

ALICE_ONLY_SEND_EMAIL = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
) when { context.input.to == "alice@example.com" };
"""


def _check(
    sample_schema: GeneratedSchema, *, old: str, new: str, session_id: str = "s1"
) -> SubsumptionOutcome:
    report = check_subsumption(
        old_policy_text=old, new_policy_text=new, schema=sample_schema, session_id=session_id
    )
    return report.outcome


def test_narrowing_from_unconditional_to_argument_constrained(
    sample_schema: GeneratedSchema,
) -> None:
    outcome = _check(sample_schema, old=UNCONDITIONAL_SEND_EMAIL, new=ALICE_ONLY_SEND_EMAIL)
    assert outcome is SubsumptionOutcome.NARROWING


def test_expansion_from_argument_constrained_to_unconditional(
    sample_schema: GeneratedSchema,
) -> None:
    report = check_subsumption(
        old_policy_text=ALICE_ONLY_SEND_EMAIL,
        new_policy_text=UNCONDITIONAL_SEND_EMAIL,
        schema=sample_schema,
        session_id="s1",
    )
    assert report.outcome is SubsumptionOutcome.EXPANSION
    violation = next(v for v in report.violations if v.action == "send_email")
    assert "counterexample" in violation.detail


def test_identical_policies_are_a_narrowing_reflexively(sample_schema: GeneratedSchema) -> None:
    outcome = _check(sample_schema, old=UNCONDITIONAL_SEND_EMAIL, new=UNCONDITIONAL_SEND_EMAIL)
    assert outcome is SubsumptionOutcome.NARROWING


def test_empty_new_policy_is_always_a_narrowing_of_anything(sample_schema: GeneratedSchema) -> None:
    outcome = _check(sample_schema, old=UNCONDITIONAL_SEND_EMAIL, new="")
    assert outcome is SubsumptionOutcome.NARROWING


def test_empty_old_policy_can_never_be_narrowed_into_by_anything_nonempty(
    sample_schema: GeneratedSchema,
) -> None:
    outcome = _check(sample_schema, old="", new=UNCONDITIONAL_SEND_EMAIL)
    assert outcome is SubsumptionOutcome.EXPANSION


def test_numeric_range_narrowing(sample_schema: GeneratedSchema) -> None:
    old = """
    permit(principal, action == AgentShield::Action::"transfer_funds", resource)
    when { context.input.amount_usd <= 1000 };
    """
    new = """
    permit(principal, action == AgentShield::Action::"transfer_funds", resource)
    when { context.input.amount_usd <= 100 };
    """
    outcome = _check(sample_schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.NARROWING


def test_numeric_range_widening_is_an_expansion(sample_schema: GeneratedSchema) -> None:
    old = """
    permit(principal, action == AgentShield::Action::"transfer_funds", resource)
    when { context.input.amount_usd <= 100 };
    """
    new = """
    permit(principal, action == AgentShield::Action::"transfer_funds", resource)
    when { context.input.amount_usd <= 1000 };
    """
    outcome = _check(sample_schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.EXPANSION


def test_a_new_forbid_clause_is_a_narrowing(sample_schema: GeneratedSchema) -> None:
    new = (
        UNCONDITIONAL_SEND_EMAIL
        + """
    forbid(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to like "*@evil.com" };
    """
    )
    outcome = _check(sample_schema, old=UNCONDITIONAL_SEND_EMAIL, new=new)
    assert outcome is SubsumptionOutcome.NARROWING


def test_removing_a_forbid_clause_is_an_expansion(sample_schema: GeneratedSchema) -> None:
    old = (
        UNCONDITIONAL_SEND_EMAIL
        + """
    forbid(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to like "*@evil.com" };
    """
    )
    outcome = _check(sample_schema, old=old, new=UNCONDITIONAL_SEND_EMAIL)
    assert outcome is SubsumptionOutcome.EXPANSION


def test_set_membership_narrowing(sample_schema: GeneratedSchema) -> None:
    old = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to in ["alice@example.com", "bob@example.com"] };
    """
    new = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to in ["alice@example.com"] };
    """
    outcome = _check(sample_schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.NARROWING


def test_set_membership_widening_is_an_expansion(sample_schema: GeneratedSchema) -> None:
    old = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to in ["alice@example.com"] };
    """
    new = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to in ["alice@example.com", "mallory@example.com"] };
    """
    outcome = _check(sample_schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.EXPANSION


def test_like_wildcard_narrowing_to_a_fixed_literal(sample_schema: GeneratedSchema) -> None:
    old = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to like "*@example.com" };
    """
    outcome = _check(sample_schema, old=old, new=ALICE_ONLY_SEND_EMAIL)
    assert outcome is SubsumptionOutcome.NARROWING


def test_like_wildcard_widening_is_an_expansion(sample_schema: GeneratedSchema) -> None:
    new = """
    permit(principal, action == AgentShield::Action::"send_email", resource)
    when { context.input.to like "*@example.com" };
    """
    outcome = _check(sample_schema, old=ALICE_ONLY_SEND_EMAIL, new=new)
    assert outcome is SubsumptionOutcome.EXPANSION


def test_unaffected_actions_remain_unconditionally_permitted_on_both_sides(
    sample_schema: GeneratedSchema,
) -> None:
    """Narrowing one action's policy must not accidentally get credited to
    an unrelated action -- `transfer_funds` is untouched by either policy
    text here, so it stays permit-everything on both sides, which is a
    trivially reflexive narrowing, not evidence this test is vacuous about
    `send_email` specifically (covered by the dedicated per-action
    assertion below).
    """
    report = check_subsumption(
        old_policy_text=UNCONDITIONAL_SEND_EMAIL,
        new_policy_text=ALICE_ONLY_SEND_EMAIL,
        schema=sample_schema,
        session_id="s1",
    )
    by_action = {r.action: r for r in report.per_action}
    assert by_action["send_email"].outcome is SubsumptionOutcome.NARROWING
    assert by_action["transfer_funds"].outcome is SubsumptionOutcome.NARROWING


def test_optional_context_attribute_referenced_in_a_condition_is_unproven() -> None:
    """An optional (non-required) context attribute is outside the
    translatable subset (see the module docstring): referencing it in a
    condition must fail closed to UNPROVEN, never be silently treated as
    a provable narrowing.
    """
    tool = {
        "name": "search",
        "description": "search",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["query"],  # `limit` is deliberately optional
        },
    }
    schema = generate_schema([tool])
    old = 'permit(principal, action == AgentShield::Action::"search", resource);'
    new = """
    permit(principal, action == AgentShield::Action::"search", resource)
    when { context.input.limit <= 10 };
    """
    outcome = _check(schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.UNPROVEN


def test_an_unsupported_number_typed_attribute_is_unproven() -> None:
    """The MCP-schema generator maps JSON Schema `"type": "number"` to a
    synthetic Cedar entity type, not a primitive this module can turn
    into a z3 sort -- referencing it in a condition must fail closed.
    """
    tool = {
        "name": "price_quote",
        "description": "quote",
        "inputSchema": {
            "type": "object",
            "properties": {"amount": {"type": "number"}},
            "required": ["amount"],
        },
    }
    schema = generate_schema([tool])
    old = 'permit(principal, action == AgentShield::Action::"price_quote", resource);'
    new = """
    permit(principal, action == AgentShield::Action::"price_quote", resource)
    when { context.input.amount <= 5 };
    """
    outcome = _check(schema, old=old, new=new)
    assert outcome is SubsumptionOutcome.UNPROVEN


def test_malformed_policy_text_is_unproven_rather_than_raising(
    sample_schema: GeneratedSchema,
) -> None:
    report = check_subsumption(
        old_policy_text=UNCONDITIONAL_SEND_EMAIL,
        new_policy_text="this is not { valid cedar at all !!!",
        schema=sample_schema,
        session_id="s1",
    )
    assert report.outcome is SubsumptionOutcome.UNPROVEN


def test_wrong_session_principal_scope_excludes_the_policy_entirely(
    sample_schema: GeneratedSchema,
) -> None:
    """A policy scoped to a different session must not count toward either
    side's permitted set for `session_id="s1"`.
    """
    other_session_policy = """
    permit(
        principal == AgentShield::Session::"s2",
        action == AgentShield::Action::"send_email",
        resource
    );
    """
    outcome = _check(sample_schema, old="", new=other_session_policy, session_id="s1")
    assert outcome is SubsumptionOutcome.NARROWING  # the s2-scoped grant is irrelevant to s1


@pytest.mark.parametrize("session_id", ["s1", "s42"])
def test_subsumption_report_covers_every_action_in_the_schema(
    sample_schema: GeneratedSchema, session_id: str
) -> None:
    report = check_subsumption(
        old_policy_text=UNCONDITIONAL_SEND_EMAIL,
        new_policy_text=UNCONDITIONAL_SEND_EMAIL,
        schema=sample_schema,
        session_id=session_id,
    )
    actions = {r.action for r in report.per_action}
    assert actions == {"send_email", "transfer_funds"}
