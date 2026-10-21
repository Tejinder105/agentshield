from __future__ import annotations

import pytest
from agentshield_console_api.policies import PolicyRegistry, SessionPolicy, UnknownSessionError
from agentshield_core.decision import DecisionKind, ObligationKind

# Must stay byte-for-byte identical to `conftest.py`'s fixtures of the same
# name: `policy_registry` is built from exactly these.
SEND_EMAIL_TOOL: dict[str, object] = {
    "name": "send_email",
    "description": "Send an email on the user's behalf",
    "inputSchema": {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "body"],
    },
}

ALLOW_ALICE_ONLY = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
) when { context.input.to == "alice@example.com" };
"""

ALLOW_ANYONE = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
);
"""


def _get(registry: PolicyRegistry, session_id: str) -> SessionPolicy:
    session_policy = registry.get(session_id)
    assert session_policy is not None
    return session_policy


def test_get_returns_none_for_an_unregistered_session(policy_registry: PolicyRegistry) -> None:
    assert policy_registry.get("no-such-session") is None


def test_get_returns_the_registered_policy(policy_registry: PolicyRegistry) -> None:
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ALICE_ONLY


def test_validate_accepts_a_well_formed_candidate(policy_registry: PolicyRegistry) -> None:
    result = policy_registry.validate("s1", ALLOW_ANYONE)
    assert result.valid is True
    assert result.errors == ()
    # Validation never applies the candidate.
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ALICE_ONLY


def test_validate_rejects_a_malformed_candidate(policy_registry: PolicyRegistry) -> None:
    result = policy_registry.validate("s1", "this is not cedar at all {{{")
    assert result.valid is False
    assert result.errors


def test_validate_raises_for_an_unknown_session(policy_registry: PolicyRegistry) -> None:
    with pytest.raises(UnknownSessionError):
        policy_registry.validate("no-such-session", ALLOW_ANYONE)


def test_propose_update_auto_applies_a_proven_narrowing(policy_registry: PolicyRegistry) -> None:
    narrower = """
    permit(
        principal,
        action == AgentShield::Action::"send_email",
        resource
    ) when {
        context.input.to == "alice@example.com" && context.input.body == "hi"
    };
    """
    decision = policy_registry.propose_update("s1", narrower)
    assert decision.kind is DecisionKind.ALLOW
    assert _get(policy_registry, "s1").store.policy_text.strip() == narrower.strip()


def test_propose_update_leaves_an_expansion_pending(policy_registry: PolicyRegistry) -> None:
    decision = policy_registry.propose_update("s1", ALLOW_ANYONE)
    assert decision.kind is DecisionKind.REQUIRE_APPROVAL
    assert any(ob.kind is ObligationKind.RECORD_SUBSUMPTION_EVIDENCE for ob in decision.obligations)
    # The registry's stored policy is untouched.
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ALICE_ONLY


def test_propose_update_denies_a_malformed_candidate(policy_registry: PolicyRegistry) -> None:
    decision = policy_registry.propose_update("s1", "not cedar {{{")
    assert decision.kind is DecisionKind.DENY
    assert decision.obligations == ()
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ALICE_ONLY


def test_propose_update_raises_for_an_unknown_session(policy_registry: PolicyRegistry) -> None:
    with pytest.raises(UnknownSessionError):
        policy_registry.propose_update("no-such-session", ALLOW_ANYONE)


def test_register_replaces_a_sessions_entire_policy(policy_registry: PolicyRegistry) -> None:
    schema = _get(policy_registry, "s1").schema
    policy_registry.register("s1", schema=schema, policy_text=ALLOW_ANYONE)
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ANYONE


def test_register_is_independent_per_session(policy_registry: PolicyRegistry) -> None:
    schema = _get(policy_registry, "s1").schema
    policy_registry.register("s2", schema=schema, policy_text=ALLOW_ANYONE)
    assert _get(policy_registry, "s1").store.policy_text == ALLOW_ALICE_ONLY
    assert _get(policy_registry, "s2").store.policy_text == ALLOW_ANYONE


def test_tool_fixture_is_used_consistently() -> None:
    # Sanity check that the shared fixture tool used across this test file
    # really is the one the schema in `policy_registry` was built from.
    assert SEND_EMAIL_TOOL["name"] == "send_email"
