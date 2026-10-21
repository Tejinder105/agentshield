from __future__ import annotations

from typing import Any

import pytest
from agentshield_confinement.synthesis import (
    DEFAULT_DENY_ALL_POLICY,
    SynthesisResult,
    synthesize_initial_policy,
)
from agentshield_core.decision import DecisionKind
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.pdp import PolicyDecisionPoint

pytestmark = pytest.mark.asyncio

VALID_POLICY = """
permit(
    principal,
    action == AgentShield::Action::"send_email",
    resource
) when { context.input.to == "alice@example.com" };
"""


class _StubSynthesizer:
    """A deterministic test double standing in for a real LLM client --
    exactly the role `agentshield_sdk.quarantine`'s `_StubQuarantinedLLM`
    plays for the sibling parsing-quarantine role.
    """

    def __init__(self, *, response: str | None = None, raises: Exception | None = None) -> None:
        self._response = response
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    async def synthesize(
        self, *, user_task: str, schema_text: str, tools: list[dict[str, Any]]
    ) -> str:
        self.calls.append({"user_task": user_task, "schema_text": schema_text, "tools": tools})
        if self._raises is not None:
            raise self._raises
        assert self._response is not None
        return self._response


async def test_a_valid_candidate_is_accepted_and_usable(sample_schema: GeneratedSchema) -> None:
    synthesizer = _StubSynthesizer(response=VALID_POLICY)
    result = await synthesize_initial_policy(
        synthesizer, user_task="email alice", schema=sample_schema, tools=[]
    )
    assert result.accepted is True
    assert result.raw_candidate == VALID_POLICY

    pdp = PolicyDecisionPoint(sample_schema, result.policy_store)
    allowed = pdp.authorize(
        session_id="s1", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert allowed.kind is DecisionKind.ALLOW


async def test_synthesizer_exception_falls_back_to_deny_all(sample_schema: GeneratedSchema) -> None:
    synthesizer = _StubSynthesizer(raises=RuntimeError("model unavailable"))
    result = await synthesize_initial_policy(
        synthesizer, user_task="email alice", schema=sample_schema, tools=[]
    )
    assert result.accepted is False
    assert result.raw_candidate == ""
    assert "model unavailable" in result.detail

    pdp = PolicyDecisionPoint(sample_schema, result.policy_store)
    denied = pdp.authorize(
        session_id="s1", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert denied.kind is DecisionKind.DENY


async def test_malformed_candidate_text_falls_back_to_deny_all(
    sample_schema: GeneratedSchema,
) -> None:
    synthesizer = _StubSynthesizer(response="this is not valid cedar {{{ at all")
    result = await synthesize_initial_policy(
        synthesizer, user_task="email alice", schema=sample_schema, tools=[]
    )
    assert result.accepted is False
    assert result.raw_candidate == "this is not valid cedar {{{ at all"

    pdp = PolicyDecisionPoint(sample_schema, result.policy_store)
    denied = pdp.authorize(
        session_id="s1", tool_name="send_email", arguments={"to": "alice@example.com", "body": "hi"}
    )
    assert denied.kind is DecisionKind.DENY


async def test_candidate_that_fails_schema_validation_falls_back_to_deny_all(
    sample_schema: GeneratedSchema,
) -> None:
    """Valid Cedar *syntax* that references a tool argument the schema
    doesn't declare must still fail closed, not just a parse error.
    """
    synthesizer = _StubSynthesizer(
        response="""
        permit(principal, action == AgentShield::Action::"send_email", resource)
        when { context.input.nonexistent_field == "x" };
        """
    )
    result = await synthesize_initial_policy(
        synthesizer, user_task="email alice", schema=sample_schema, tools=[]
    )
    assert result.accepted is False


async def test_the_synthesizer_is_called_with_the_task_and_schema_text(
    sample_schema: GeneratedSchema,
) -> None:
    synthesizer = _StubSynthesizer(response=VALID_POLICY)
    await synthesize_initial_policy(
        synthesizer,
        user_task="email alice about the quarterly report",
        schema=sample_schema,
        tools=[],
    )
    assert len(synthesizer.calls) == 1
    assert synthesizer.calls[0]["user_task"] == "email alice about the quarterly report"
    assert synthesizer.calls[0]["schema_text"] == sample_schema.schema_text


async def test_default_deny_all_policy_text_is_itself_valid_cedar(
    sample_schema: GeneratedSchema,
) -> None:
    """The fallback constant must parse cleanly on its own -- a comment-only
    policy document is valid, empty Cedar, not an edge case that would
    itself raise during construction.
    """
    from agentshield_policy.policies import PolicyStore

    store = PolicyStore(policy_text=DEFAULT_DENY_ALL_POLICY, schema=sample_schema)
    assert store.policy_text == DEFAULT_DENY_ALL_POLICY


async def test_synthesis_result_is_a_frozen_dataclass() -> None:
    import dataclasses

    assert dataclasses.is_dataclass(SynthesisResult)
