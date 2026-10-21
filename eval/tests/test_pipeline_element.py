from __future__ import annotations

import dataclasses
from typing import Any

from agentdojo.functions_runtime import EmptyEnv, FunctionCall, FunctionsRuntime
from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_eval.pipeline_element import AgentShieldToolsExecutor
from agentshield_eval.tool_profiles import ToolSecurityClass
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus
from agentshield_gateway.registry import ToolRegistry, ToolSecurityProfile
from agentshield_gateway.schema_pinning import PinnedToolSet
from agentshield_gateway.session import GatewaySession
from agentshield_ledger.ledger import Ledger
from agentshield_policy.mcp_schema import generate_schema
from agentshield_policy.pdp import PolicyDecisionPoint
from agentshield_policy.policies import PolicyStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PERMIT_ALL_POLICY = "permit(principal, action, resource);"
DENY_SEND_MESSAGE_POLICY = """
permit(principal, action == AgentShield::Action::"read_message", resource);
permit(principal, action == AgentShield::Action::"read_secret", resource);
permit(principal, action == AgentShield::Action::"return_a_float", resource);
permit(principal, action == AgentShield::Action::"broken_tool", resource);
"""


def _assistant_message(tool_calls: list[FunctionCall]) -> dict[str, Any]:
    return {"role": "assistant", "content": None, "tool_calls": tool_calls}


def _build_pipeline_and_session(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    *,
    policy_text: str,
) -> tuple[DecisionPipeline, GatewaySession, Ledger]:
    schema = generate_schema(demo_tool_dicts)
    store = PolicyStore(policy_text=policy_text, schema=schema)
    pdp = PolicyDecisionPoint(schema, store)

    registry = ToolRegistry()
    for name, tool_class in demo_tool_classes.items():
        registry.register(name, tool_class.profile)

    session = GatewaySession(session_id="demo-session")
    session.pinned_tools = PinnedToolSet.pin(demo_tool_dicts)
    for tool in demo_tool_dicts:
        session.grant_capability(Capability.mint("demo-session", tool["name"], 0, 3600.0))

    ledger = Ledger(signing_key=Ed25519PrivateKey.generate())
    pipeline = DecisionPipeline(policy_decision_point=pdp, ledger=ledger, tool_registry=registry)
    return pipeline, session, ledger


def _executor(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    *,
    policy_text: str = PERMIT_ALL_POLICY,
) -> tuple[AgentShieldToolsExecutor, Ledger]:
    pipeline, session, ledger = _build_pipeline_and_session(
        demo_tool_dicts, demo_tool_classes, policy_text=policy_text
    )
    executor = AgentShieldToolsExecutor(
        pipeline,
        session,
        tool_schemas={tool["name"]: tool for tool in demo_tool_dicts},
        tool_classes=demo_tool_classes,
    )
    return executor, ledger


def test_no_tool_calls_passes_messages_through_unchanged(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    messages = [_assistant_message([])]
    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})
    assert out_messages == messages
    assert executor.decisions == []


def test_allowed_call_dispatches_and_formats_result(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    call = FunctionCall(function="send_message", args={"body": "hi"}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    tool_result = out_messages[-1]
    assert tool_result["role"] == "tool"
    assert tool_result["error"] is None
    assert "sent: hi" in tool_result["content"][0]["content"]
    assert len(executor.decisions) == 1
    assert executor.decisions[0].status is OutcomeStatus.DISPATCHED
    assert executor.decisions[0].tool_name == "send_message"


def test_cedar_denial_never_reaches_the_runtime(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, _ = _executor(
        demo_tool_dicts, demo_tool_classes, policy_text=DENY_SEND_MESSAGE_POLICY
    )
    call = FunctionCall(function="send_message", args={"body": "hi"}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    tool_result = out_messages[-1]
    assert tool_result["error"] is not None
    assert tool_result["error"].startswith("AgentShieldDenied")
    assert executor.decisions[0].status is OutcomeStatus.DENIED
    assert executor.decisions[0].decision.stage == "cedar_policy"


def test_information_flow_ceiling_blocks_egress_after_an_untrusted_read(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    """Reading an untrusted message taints the session's integrity to
    `UNTRUSTED`; the egress tool's ceiling then requires at least
    `TENTATIVE` integrity, so the very next egress call is denied at
    the information-flow stage, before the trifecta check ever runs.
    """
    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    read_call = FunctionCall(function="read_message", args={}, id="1")
    send_call = FunctionCall(function="send_message", args={"body": "exfil"}, id="2")

    before_read = [_assistant_message([read_call])]
    _, _, _, after_read, _ = executor.query("q", demo_runtime, EmptyEnv(), before_read, {})
    assert executor.decisions[-1].status is OutcomeStatus.DISPATCHED

    before_send = [*after_read, _assistant_message([send_call])]
    _, _, _, after_send, _ = executor.query("q", demo_runtime, EmptyEnv(), before_send, {})

    tool_result = after_send[-1]
    assert tool_result["error"] is not None
    assert tool_result["error"].startswith("AgentShieldDenied")
    assert executor.decisions[-1].decision.stage == "information_flow"


def test_lethal_trifecta_denies_the_call_that_would_complete_it(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    """Isolates the trifecta check (step 6) from the ceiling check (step
    5) by widening `send_message`'s ceiling to `Label.top()` for this
    test only, so a session that has acquired both other legs is denied
    specifically *because* sending would complete the trifecta, not
    because of accumulated label taint.
    """
    classes = dict(demo_tool_classes)
    classes["send_message"] = dataclasses.replace(
        classes["send_message"],
        profile=ToolSecurityProfile(
            ceiling=Label.top(), trifecta_leg=classes["send_message"].profile.trifecta_leg
        ),
    )
    executor, _ = _executor(demo_tool_dicts, classes)

    for name in ("read_message", "read_secret"):
        call = FunctionCall(function=name, args={}, id=name)
        before = [_assistant_message([call])]
        executor.query("q", demo_runtime, EmptyEnv(), before, {})
        assert executor.decisions[-1].status is OutcomeStatus.DISPATCHED

    send_call = FunctionCall(function="send_message", args={"body": "exfil"}, id="3")
    before_send = [_assistant_message([send_call])]
    _, _, _, after_send, _ = executor.query("q", demo_runtime, EmptyEnv(), before_send, {})

    tool_result = after_send[-1]
    assert tool_result["error"] is not None
    assert executor.decisions[-1].status is OutcomeStatus.DENIED
    assert executor.decisions[-1].decision.stage == "trifecta"


def test_dispatch_failure_is_recorded_as_uncertain(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    call = FunctionCall(function="broken_tool", args={}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    tool_result = out_messages[-1]
    assert tool_result["error"] is not None
    assert "uncertain" in tool_result["error"]
    assert executor.decisions[0].status is OutcomeStatus.DISPATCH_FAILED_UNCERTAIN


def test_float_results_are_sanitized_before_reaching_the_ledger(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, ledger = _executor(demo_tool_dicts, demo_tool_classes)
    call = FunctionCall(function="return_a_float", args={}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    assert out_messages[-1]["error"] is None
    last_entry = ledger.entries[-1]
    assert "10.5" in str(last_entry.entry["payload"])

    def _assert_no_float(value: Any) -> None:
        assert not isinstance(value, float)
        if isinstance(value, dict):
            for v in value.values():
                _assert_no_float(v)
        if isinstance(value, list):
            for v in value:
                _assert_no_float(v)

    _assert_no_float(last_entry.entry["payload"])


def test_empty_function_name_is_handled_without_reaching_the_pipeline(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME

    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    call = FunctionCall(function=EMPTY_FUNCTION_NAME, args={}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    assert out_messages[-1]["error"] == (
        "Empty function name provided. Provide a valid function name."
    )
    assert executor.decisions == []


def test_unknown_tool_name_is_handled_without_reaching_the_pipeline(
    demo_tool_dicts: list[dict[str, Any]],
    demo_tool_classes: dict[str, ToolSecurityClass],
    demo_runtime: FunctionsRuntime,
) -> None:
    executor, _ = _executor(demo_tool_dicts, demo_tool_classes)
    call = FunctionCall(function="does_not_exist", args={}, id="1")
    messages = [_assistant_message([call])]

    _, _, _, out_messages, _ = executor.query("q", demo_runtime, EmptyEnv(), messages, {})

    assert out_messages[-1]["error"] == "Invalid tool does_not_exist provided."
    assert executor.decisions == []
