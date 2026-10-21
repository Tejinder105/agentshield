from __future__ import annotations

from agentshield_core.decision import DecisionKind
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore

ALLOW_ALICE_ONLY = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.to == "alice@example.com" };
"""

ALLOW_SMALL_TRANSFERS = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"transfer_funds",
    resource == AgentShield::Tool::"transfer_funds"
) when { context.input.amount_usd <= 100 };
"""


def _pdp(schema: GeneratedSchema, policy_text: str) -> PolicyDecisionPoint:
    store = PolicyStore(policy_text=policy_text, schema=schema)
    return PolicyDecisionPoint(schema, store)


def test_allowed_call_within_policy(sample_schema: GeneratedSchema) -> None:
    pdp = _pdp(sample_schema, ALLOW_ALICE_ONLY)
    decision = pdp.authorize(
        session_id="s1", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert decision.kind is DecisionKind.ALLOW
    assert decision.stage == "cedar_policy"


def test_denied_call_outside_policy_argument_constraint(sample_schema: GeneratedSchema) -> None:
    pdp = _pdp(sample_schema, ALLOW_ALICE_ONLY)
    decision = pdp.authorize(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
    )
    assert decision.kind is DecisionKind.DENY


def test_denied_call_for_a_tool_with_no_matching_policy(sample_schema: GeneratedSchema) -> None:
    pdp = _pdp(sample_schema, ALLOW_ALICE_ONLY)  # no rule at all for transfer_funds
    decision = pdp.authorize(
        session_id="s1", tool_name="transfer_funds", arguments={"to_account": "x", "amount_usd": 5}
    )
    assert decision.kind is DecisionKind.DENY


def test_denied_for_wrong_session_principal(sample_schema: GeneratedSchema) -> None:
    """A policy scoped to session s1 must not authorize a call made under a
    different session id -- this is the least-privilege boundary between
    sessions.
    """
    pdp = _pdp(sample_schema, ALLOW_ALICE_ONLY)
    decision = pdp.authorize(
        session_id="s2", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert decision.kind is DecisionKind.DENY


def test_numeric_argument_constraint_enforced(sample_schema: GeneratedSchema) -> None:
    pdp = _pdp(sample_schema, ALLOW_SMALL_TRANSFERS)
    small = pdp.authorize(
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"to_account": "acct-1", "amount_usd": 50},
    )
    large = pdp.authorize(
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"to_account": "acct-1", "amount_usd": 5000},
    )
    assert small.kind is DecisionKind.ALLOW
    assert large.kind is DecisionKind.DENY


def test_default_deny_with_empty_policy_set(sample_schema: GeneratedSchema) -> None:
    """No policy at all must deny everything -- Cedar's own default-deny
    semantics, exercised end-to-end through our PDP wrapper.
    """
    pdp = _pdp(sample_schema, "")
    decision = pdp.authorize(
        session_id="s1", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert decision.kind is DecisionKind.DENY


def test_malformed_arguments_fail_closed_rather_than_raising(
    sample_schema: GeneratedSchema,
) -> None:
    """Even pathological input must come back as a Decision, never an
    unhandled exception escaping the PDP boundary.
    """
    pdp = _pdp(sample_schema, ALLOW_ALICE_ONLY)
    decision = pdp.authorize(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": {"nested": "not-a-string"}, "body": object()},
    )
    assert decision.kind is DecisionKind.DENY
