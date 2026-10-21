"""End-to-end session lifecycle: LLM-synthesized initial policy, used for
real authorization decisions through `agentshield_policy.PolicyDecisionPoint`,
then narrowed twice (auto-applied) and finally subjected to one expansion
attempt (rejected, left pending for a human). This is the full "monotonic
confinement" story from the plan in one test, exercising
`agentshield-confinement` together with `agentshield-policy` and
`agentshield-core` exactly as a real caller (the gateway, eventually)
would.
"""

from __future__ import annotations

from typing import Any

import pytest
from agentshield_confinement.gate import propose_policy_update
from agentshield_confinement.synthesis import synthesize_initial_policy
from agentshield_core.decision import DecisionKind
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.pdp import PolicyDecisionPoint

pytestmark = pytest.mark.asyncio


class _TaskAwareSynthesizer:
    """Stands in for a real policy-synthesis LLM: produces a plausible
    first-cut policy for "email alice about the report" that permits
    `send_email` unconditionally and says nothing about `transfer_funds`
    (default-deny covers it) -- exactly the kind of coarse, slightly
    over-broad starting point monotonic confinement exists to narrow down
    from without ever needing to widen it again.
    """

    async def synthesize(
        self, *, user_task: str, schema_text: str, tools: list[dict[str, Any]]
    ) -> str:
        assert "email" in user_task
        return """
        permit(
            principal,
            action == AgentShield::Action::"send_email",
            resource
        );
        """


async def test_full_session_lifecycle_synthesis_then_two_narrowings_then_a_rejected_expansion(
    sample_schema: GeneratedSchema,
) -> None:
    # 1. Session start: synthesize the initial policy from the user's task.
    synthesis = await synthesize_initial_policy(
        _TaskAwareSynthesizer(),
        user_task="email alice about the quarterly report",
        schema=sample_schema,
        tools=[],
    )
    assert synthesis.accepted is True
    store = synthesis.policy_store

    pdp = PolicyDecisionPoint(sample_schema, store)
    # The synthesized policy is broad: anyone's email is currently permitted.
    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "mallory@example.com", "body": "hi"},
        ).kind
        is DecisionKind.ALLOW
    )
    # And the untouched tool is still default-deny.
    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="transfer_funds",
            arguments={"to_account": "acct-1", "amount_usd": 10},
        ).kind
        is DecisionKind.DENY
    )

    # 2. First narrowing: restrict `send_email` to one known-good address.
    narrowing_one = """
    permit(
        principal,
        action == AgentShield::Action::"send_email",
        resource
    ) when { context.input.to == "alice@example.com" };
    """
    first = propose_policy_update(store, narrowing_one, schema=sample_schema, session_id="s1")
    assert first.kind is DecisionKind.ALLOW  # proven narrowing, auto-applied

    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "mallory@example.com", "body": "hi"},
        ).kind
        is DecisionKind.DENY
    )
    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "alice@example.com", "body": "hi"},
        ).kind
        is DecisionKind.ALLOW
    )

    # 3. Second narrowing, composed on top of the first: also pin the body text.
    narrowing_two = """
    permit(
        principal,
        action == AgentShield::Action::"send_email",
        resource
    ) when {
        context.input.to == "alice@example.com" &&
        context.input.body == "quarterly report attached"
    };
    """
    second = propose_policy_update(store, narrowing_two, schema=sample_schema, session_id="s1")
    assert second.kind is DecisionKind.ALLOW

    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "alice@example.com", "body": "something else"},
        ).kind
        is DecisionKind.DENY
    )
    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "alice@example.com", "body": "quarterly report attached"},
        ).kind
        is DecisionKind.ALLOW
    )

    # 4. A hijacked planner now tries to widen back to "any recipient" --
    #    even if dressed up as a legitimate-looking update, it must be
    #    *proven* a narrowing to auto-apply, and widening never is.
    attempted_escalation = """
    permit(
        principal,
        action == AgentShield::Action::"send_email",
        resource
    );
    """
    escalation = propose_policy_update(
        store, attempted_escalation, schema=sample_schema, session_id="s1"
    )
    assert escalation.kind is DecisionKind.REQUIRE_APPROVAL
    assert store.policy_text == narrowing_two  # the escalation never took effect

    # The session's action space is exactly where the second narrowing left
    # it: a hijacked planner cannot escalate its own privileges on its own.
    assert (
        pdp.authorize(
            session_id="s1",
            tool_name="send_email",
            arguments={"to": "mallory@example.com", "body": "attacker payload"},
        ).kind
        is DecisionKind.DENY
    )
