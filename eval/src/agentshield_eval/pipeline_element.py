"""`AgentShieldToolsExecutor`: a drop-in replacement for AgentDojo's
`agentdojo.agent_pipeline.tool_execution.ToolsExecutor` that routes every
tool call the planner LLM proposes through a real
`agentshield_gateway.pipeline.DecisionPipeline` before it ever touches the
task's live `FunctionsRuntime`/`Env`, instead of re-implementing
enforcement logic just for the benchmark.

Malformed-call handling (an empty function name, a tool name the runtime
does not know about, the string-encoded-list argument coercion) is
copied verbatim from the stock `ToolsExecutor` rather than reinvented,
because those are AgentDojo plumbing concerns, not Agent Shield security
decisions -- a benchmark run must see identical behavior for *that* class
of error whether or not Agent Shield is in the loop, so that any utility
or security delta measured is attributable to Agent Shield's own
decisions alone.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import time
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string
from agentshield_core.decision import Decision
from agentshield_core.labels import Label
from agentshield_gateway.dispatch import InMemoryToolDispatcher
from agentshield_gateway.pipeline import (
    DecisionPipeline,
    GatewayOutcome,
    OutcomeStatus,
    ToolCallRequest,
)
from agentshield_gateway.session import GatewaySession
from pydantic import BaseModel

from agentshield_eval.tool_profiles import ToolSecurityClass


def _json_safe(value: Any) -> Any:
    """Recursively converts `value` into something the ledger's
    float-rejecting RFC 8785 canonicalizer (see
    `agentshield_ledger.verify.canonical`) can serialize, without
    discarding information: floats become their `str()` (exact decimal
    text, not a silently-truncated int), `BaseModel`s become plain
    dicts, and everything else JSON-shaped passes through unchanged.
    """
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, float):
        return str(value)
    if isinstance(value, BaseModel):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int)):
        return value
    return str(value)


@dataclasses.dataclass(frozen=True, slots=True)
class RecordedToolCallDecision:
    """One tool call's Agent Shield verdict, kept around for the
    per-pillar ablation and adaptive-attack analysis in
    `agentshield_eval.ablation` and `agentshield_eval.adaptive_attacks` --
    AgentDojo's own `TaskResults` only records utility/security booleans,
    not *why* the pipeline reached them.
    """

    tool_name: str
    arguments: dict[str, Any]
    status: OutcomeStatus
    decision: Decision
    at: float


# agentdojo ships no `py.typed`, so `BasePipelineElement` is `Any` under
# our `ignore_missing_imports` override; subclassing it is still the
# integration the plan requires.
class AgentShieldToolsExecutor(BasePipelineElement):  # type: ignore[misc]
    """Executes the tool calls in the last assistant message, exactly
    like `ToolsExecutor`, except every call is first evaluated by `pipeline`
    against `session`. A denial never reaches the live `runtime`/`env` at
    all; it is turned into a `ChatToolResultMessage` carrying the
    pipeline's own denial reason as the tool error, so the planner sees a
    refusal in-band, the same way it would see any other tool failure.
    """

    def __init__(
        self,
        pipeline: DecisionPipeline,
        session: GatewaySession,
        *,
        tool_schemas: dict[str, dict[str, Any]],
        tool_classes: dict[str, ToolSecurityClass] | None = None,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self._pipeline = pipeline
        self._session = session
        self._tool_schemas = tool_schemas
        self._tool_classes = tool_classes or {}
        self._output_formatter = tool_output_formatter
        self.decisions: list[RecordedToolCallDecision] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),  # noqa: B008
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},  # noqa: B006
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        last_message = messages[-1]
        if last_message["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = last_message["tool_calls"]
        if tool_calls is None or len(tool_calls) == 0:
            return query, runtime, env, messages, extra_args

        results: list[ChatToolResultMessage] = []
        for tool_call in tool_calls:
            results.append(self._execute_one(tool_call, runtime, env))
        return query, runtime, env, [*messages, *results], extra_args

    def _execute_one(
        self, tool_call: Any, runtime: FunctionsRuntime, env: Env
    ) -> ChatToolResultMessage:
        if tool_call.function == EMPTY_FUNCTION_NAME:
            return ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string("")],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error="Empty function name provided. Provide a valid function name.",
            )
        if tool_call.function not in (tool.name for tool in runtime.functions.values()):
            return ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string("")],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error=f"Invalid tool {tool_call.function} provided.",
            )

        # Converts type of input lists from string to list type, exactly
        # as the stock `ToolsExecutor` does.
        for arg_k, arg_v in tool_call.args.items():
            if isinstance(arg_v, str) and is_string_list(arg_v):
                tool_call.args[arg_k] = ast.literal_eval(arg_v)

        tool_class = self._tool_classes.get(tool_call.function)
        read_label = tool_class.read_label if tool_class is not None else Label.bottom()
        request = ToolCallRequest(
            session_id=self._session.session_id,
            tool_name=tool_call.function,
            arguments=dict(tool_call.args),
            # `KeyPrincipalResolver` (pipeline step 1's default) reads this
            # key out of `raw_context`; a benchmark session has exactly one
            # fixed principal for its whole run, so it is simplest to just
            # assert it here rather than plumb a real identity layer through
            # AgentDojo's call sites.
            raw_context={"principal": self._session.session_id},
            input_label=read_label,
            current_tool_schema=self._tool_schemas.get(tool_call.function),
        )
        dispatcher = InMemoryToolDispatcher(
            {tool_call.function: self._make_handler(runtime, env, tool_call.function)}
        )
        outcome = asyncio.run(
            self._pipeline.evaluate_and_dispatch(request, self._session, dispatcher)
        )
        self.decisions.append(
            RecordedToolCallDecision(
                tool_name=tool_call.function,
                arguments=dict(tool_call.args),
                status=outcome.status,
                decision=outcome.decision,
                at=time.time(),
            )
        )
        return self._to_chat_message(tool_call, outcome)

    def _make_handler(
        self, runtime: FunctionsRuntime, env: Env, tool_name: str
    ) -> Callable[[dict[str, Any]], Any]:
        async def handler(arguments: dict[str, Any]) -> dict[str, Any]:
            result, error = runtime.run_function(env, tool_name, arguments, raise_on_error=False)
            if error is not None:
                raise RuntimeError(error)
            safe = _json_safe(result)
            return safe if isinstance(safe, dict) else {"value": safe}

        return handler

    def _to_chat_message(self, tool_call: Any, outcome: GatewayOutcome) -> ChatToolResultMessage:
        if outcome.status is OutcomeStatus.DENIED:
            return ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string("")],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error=f"AgentShieldDenied ({outcome.decision.stage}): {outcome.decision.reason}",
            )
        if outcome.status is OutcomeStatus.DISPATCH_FAILED_UNCERTAIN:
            return ChatToolResultMessage(
                role="tool",
                content=[text_content_block_from_string("")],
                tool_call_id=tool_call.id,
                tool_call=tool_call,
                error="tool dispatch failed after Agent Shield authorized the call "
                "(outcome recorded as uncertain in the ledger)",
            )
        formatted = self._output_formatter(outcome.result)
        return ChatToolResultMessage(
            role="tool",
            content=[text_content_block_from_string(formatted)],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=None,
        )
