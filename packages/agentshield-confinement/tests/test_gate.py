from __future__ import annotations

from agentshield_confinement.gate import propose_policy_update
from agentshield_core.decision import DecisionKind, ObligationKind
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore

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


def test_a_narrowing_candidate_is_auto_applied(sample_schema: GeneratedSchema) -> None:
    store = PolicyStore(policy_text=UNCONDITIONAL_SEND_EMAIL, schema=sample_schema)

    decision = propose_policy_update(
        store, ALICE_ONLY_SEND_EMAIL, schema=sample_schema, session_id="s1"
    )

    assert decision.kind is DecisionKind.ALLOW
    assert store.policy_text == ALICE_ONLY_SEND_EMAIL

    pdp = PolicyDecisionPoint(sample_schema, store)
    mallory = pdp.authorize(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
    )
    assert mallory.kind is DecisionKind.DENY


def test_an_expansion_candidate_is_rejected_and_left_pending(
    sample_schema: GeneratedSchema,
) -> None:
    store = PolicyStore(policy_text=ALICE_ONLY_SEND_EMAIL, schema=sample_schema)

    decision = propose_policy_update(
        store, UNCONDITIONAL_SEND_EMAIL, schema=sample_schema, session_id="s1"
    )

    assert decision.kind is DecisionKind.REQUIRE_APPROVAL
    assert store.policy_text == ALICE_ONLY_SEND_EMAIL  # untouched

    pdp = PolicyDecisionPoint(sample_schema, store)
    mallory = pdp.authorize(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com", "body": "hi"},
    )
    assert mallory.kind is DecisionKind.DENY  # the expansion never took effect


def test_require_approval_carries_the_subsumption_report_as_an_obligation(
    sample_schema: GeneratedSchema,
) -> None:
    store = PolicyStore(policy_text=ALICE_ONLY_SEND_EMAIL, schema=sample_schema)

    decision = propose_policy_update(
        store, UNCONDITIONAL_SEND_EMAIL, schema=sample_schema, session_id="s1"
    )

    assert len(decision.obligations) == 1
    obligation = decision.obligations[0]
    assert obligation.kind is ObligationKind.RECORD_SUBSUMPTION_EVIDENCE
    report = obligation.detail["report"]
    assert report["outcome"] == "EXPANSION"
    send_email_entry = next(
        entry for entry in report["per_action"] if entry["action"] == "send_email"
    )
    assert send_email_entry["outcome"] == "EXPANSION"


def test_a_malformed_candidate_is_denied_without_consulting_subsumption_at_all(
    sample_schema: GeneratedSchema,
) -> None:
    store = PolicyStore(policy_text=UNCONDITIONAL_SEND_EMAIL, schema=sample_schema)

    decision = propose_policy_update(
        store, "this is not valid cedar {{{ at all", schema=sample_schema, session_id="s1"
    )

    assert decision.kind is DecisionKind.DENY
    assert decision.obligations == ()
    assert store.policy_text == UNCONDITIONAL_SEND_EMAIL  # untouched


def test_an_unprovable_candidate_also_requires_approval_not_auto_apply(
    sample_schema: GeneratedSchema,
) -> None:
    """A candidate referencing an unsupported construct must be routed to
    a human exactly like a proven expansion -- fail-closed, never
    silently treated as a narrowing just because the checker couldn't
    disprove it.
    """
    from agentshield_policy.mcp_schema import generate_schema

    tool = {
        "name": "search",
        "description": "search",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["query"],  # `limit` optional -> unsupported in a condition
        },
    }
    schema = generate_schema([tool])
    store = PolicyStore(
        policy_text='permit(principal, action == AgentShield::Action::"search", resource);',
        schema=schema,
    )

    candidate = """
    permit(principal, action == AgentShield::Action::"search", resource)
    when { context.input has limit && context.input.limit <= 10 };
    """
    decision = propose_policy_update(store, candidate, schema=schema, session_id="s1")

    assert decision.kind is DecisionKind.REQUIRE_APPROVAL
    report = decision.obligations[0].detail["report"]
    assert report["outcome"] == "UNPROVEN"


def test_applying_a_second_narrowing_on_top_of_the_first_keeps_narrowing(
    sample_schema: GeneratedSchema,
) -> None:
    """Monotonic confinement is meant to compose: narrowing from an
    already-narrowed policy must still auto-apply as long as it narrows
    further.
    """
    store = PolicyStore(policy_text=UNCONDITIONAL_SEND_EMAIL, schema=sample_schema)
    first = propose_policy_update(
        store, ALICE_ONLY_SEND_EMAIL, schema=sample_schema, session_id="s1"
    )
    assert first.kind is DecisionKind.ALLOW

    even_narrower = """
    permit(
        principal,
        action == AgentShield::Action::"send_email",
        resource
    ) when { context.input.to == "alice@example.com" && context.input.body == "hi" };
    """
    second = propose_policy_update(store, even_narrower, schema=sample_schema, session_id="s1")
    assert second.kind is DecisionKind.ALLOW
    assert store.policy_text == even_narrower
