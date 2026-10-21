from __future__ import annotations

import pytest
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.policies import PolicyStore, PolicyValidationError

GOOD_POLICY = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.to == "alice@example.com" };
"""

TYPO_POLICY = """
permit(
    principal == AgentShield::Session::"s1",
    action == AgentShield::Action::"send_email",
    resource == AgentShield::Tool::"send_email"
) when { context.input.recipient == "alice@example.com" };
"""

UNPARSEABLE_POLICY = "this is not cedar at all {{{"


def test_valid_policy_loads_successfully(sample_schema: GeneratedSchema) -> None:
    store = PolicyStore(policy_text=GOOD_POLICY, schema=sample_schema)
    assert store.policy_set is not None


def test_typo_in_context_attribute_is_caught_by_schema_validation(
    sample_schema: GeneratedSchema,
) -> None:
    """This is the entire point of validating against the generated schema:
    a typo'd argument name (`recipient` instead of `to`) would otherwise
    silently never match, failing open from the operator's perspective
    (the policy looks like it grants access but never actually does, or
    vice versa for a forbid rule). Validation catches it before deploy.
    """
    with pytest.raises(PolicyValidationError) as exc_info:
        PolicyStore(policy_text=TYPO_POLICY, schema=sample_schema)
    assert any("recipient" in e for e in exc_info.value.errors)


def test_unparseable_policy_text_is_rejected(sample_schema: GeneratedSchema) -> None:
    with pytest.raises(PolicyValidationError):
        PolicyStore(policy_text=UNPARSEABLE_POLICY, schema=sample_schema)


def test_reload_with_valid_policy_succeeds(sample_schema: GeneratedSchema) -> None:
    store = PolicyStore(policy_text=GOOD_POLICY, schema=sample_schema)
    narrower_policy = GOOD_POLICY.replace("alice@example.com", "bob@example.com")
    store.reload(narrower_policy)
    assert "bob@example.com" in store.policy_text


def test_reload_with_invalid_policy_leaves_old_policy_set_untouched(
    sample_schema: GeneratedSchema,
) -> None:
    """A bad reload must never leave the PDP without a usable policy -- an
    availability bug here would be just as serious as a security bug.
    """
    store = PolicyStore(policy_text=GOOD_POLICY, schema=sample_schema)
    original_set = store.policy_set
    with pytest.raises(PolicyValidationError):
        store.reload(TYPO_POLICY)
    assert store.policy_set is original_set
    assert store.policy_text == GOOD_POLICY
