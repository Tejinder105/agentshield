from __future__ import annotations

from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatMessage, text_content_block_from_string
from agentshield_eval.harness import build_agent_shield_pipeline, build_harness
from agentshield_eval.pipeline_element import AgentShieldToolsExecutor

PERMIT_ALL_POLICY = "permit(principal, action, resource);"


def test_build_harness_classifies_and_pins_every_banking_tool() -> None:
    suite = get_suite("v1.2.2", "banking")
    harness = build_harness(suite, session_id="s1", policy_text=PERMIT_ALL_POLICY)

    for function in suite.tools:
        assert harness.tool_registry.get(function.name) is not None, function.name
        tool_dict = harness.tool_schemas[function.name]
        assert harness.session.pinned_tools.check(function.name, tool_dict)
        capability = harness.session.capabilities.get(function.name)
        assert capability is not None, function.name
        assert not capability.is_expired()
        assert capability.is_current_epoch(0)


def test_build_harness_honors_an_explicit_tool_classes_override() -> None:
    """An explicit, empty `tool_classes` map means no tool is registered
    in the resulting `ToolRegistry` at all -- every call to any banking
    tool would then be denied at the information-flow stage for lacking
    a registered security profile, which is the gateway's own documented
    fail-closed behavior for an unclassified tool.
    """
    suite = get_suite("v1.2.2", "banking")
    harness = build_harness(suite, session_id="s1", policy_text=PERMIT_ALL_POLICY, tool_classes={})
    for function in suite.tools:
        assert harness.tool_registry.get(function.name) is None


class _StubLLM(BasePipelineElement):  # type: ignore[misc]
    name = "stub-llm"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),  # noqa: B008
        messages: list[ChatMessage] | tuple[ChatMessage, ...] = (),
        extra_args: dict[str, Any] = {},  # noqa: B006
    ) -> tuple[str, FunctionsRuntime, Env, list[ChatMessage], dict[str, Any]]:
        response: ChatMessage = {
            "role": "assistant",
            "content": [text_content_block_from_string("done, no tools needed")],
            "tool_calls": [],
        }
        return query, runtime, env, [*messages, response], extra_args


def test_build_agent_shield_pipeline_assembles_and_runs_end_to_end() -> None:
    suite = get_suite("v1.2.2", "banking")
    llm = _StubLLM()

    benchmark_pipeline = build_agent_shield_pipeline(
        llm, suite, session_id="s1", policy_text=PERMIT_ALL_POLICY
    )

    assert isinstance(benchmark_pipeline.executor, AgentShieldToolsExecutor)
    assert benchmark_pipeline.pipeline.name == "stub-llm-agent-shield"

    runtime = FunctionsRuntime(suite.tools)
    _, _, _, messages, _ = benchmark_pipeline.pipeline.query("do the task", runtime, EmptyEnv())

    assert messages[-1]["role"] == "assistant"
    assert benchmark_pipeline.executor.decisions == []
