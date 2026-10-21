from __future__ import annotations

from agentshield_policy.mcp_schema import GeneratedSchema, digest_tools, generate_schema


def test_generate_schema_produces_one_action_per_tool(
    sample_tools: list[dict[str, object]],
) -> None:
    schema = generate_schema(sample_tools)
    assert "send_email" in schema.schema_json["AgentShield"]["actions"]
    assert "transfer_funds" in schema.schema_json["AgentShield"]["actions"]


def test_entity_uid_escapes_quotes_safely() -> None:
    schema = GeneratedSchema(
        namespace="AgentShield", schema_text="", schema_json={}, tools_digest=""
    )
    uid = schema.entity_uid("Session", 'weird"session')
    assert uid == 'AgentShield::Session::"weird\\"session"'


def test_action_uid_format() -> None:
    schema = GeneratedSchema(
        namespace="AgentShield", schema_text="", schema_json={}, tools_digest=""
    )
    assert schema.action_uid("send_email") == 'AgentShield::Action::"send_email"'


def test_digest_is_stable_for_identical_input(sample_tools: list[dict[str, object]]) -> None:
    assert digest_tools(sample_tools) == digest_tools(sample_tools)


def test_digest_is_order_independent_for_dict_keys(sample_tools: list[dict[str, object]]) -> None:
    """The digest must be a function of the tool list's *content*, not of
    incidental key ordering -- this is what makes it safe to use for
    rug-pull detection without false positives from re-serialization.
    """
    reordered = [dict(reversed(list(tool.items()))) for tool in sample_tools]
    assert digest_tools(sample_tools) == digest_tools(reordered)


def test_digest_changes_when_a_tool_description_changes(
    sample_tools: list[dict[str, object]],
) -> None:
    """This is the rug-pull detector's core property: any change to a
    tool's advertised schema or description must change the digest.
    """
    mutated = [dict(sample_tools[0]), sample_tools[1]]
    mutated[0]["description"] = "Totally different behavior now"
    assert digest_tools(sample_tools) != digest_tools(mutated)
