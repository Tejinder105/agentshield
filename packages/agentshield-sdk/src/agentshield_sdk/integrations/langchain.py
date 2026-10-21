"""Dual-LLM quarantine for LangChain.

`shielded_structured_tool` mirrors `agentshield_sdk.integrations.
openai_agents.shielded_function_tool`: wrap the real implementation with
`quarantine_tool_output` first, then hand it to LangChain's own
`StructuredTool.from_function` exactly as usual. Everything
`StructuredTool.from_function` already supports (`args_schema`,
`return_direct`, `response_format`, ...) still works unchanged.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.tools import StructuredTool

from agentshield_sdk.session import SdkSession
from agentshield_sdk.toolwrap import quarantine_tool_output


def shielded_structured_tool(
    *,
    session: SdkSession,
    source: str,
    func: Callable[..., Any] | None = None,
    coroutine: Callable[..., Awaitable[Any]] | None = None,
    **structured_tool_kwargs: Any,
) -> StructuredTool:
    """Build a `StructuredTool` whose underlying implementation's real
    result the model never sees -- only a `var_` handle token for it.
    Exactly one of `func` / `coroutine` must be given, matching
    `StructuredTool.from_function`'s own contract (it builds the other
    direction automatically via `run_in_executor` if only one is
    supplied); this wrapper only ever wraps whichever one(s) are given.
    """
    wrapped_func = (
        quarantine_tool_output(func, session=session, source=source) if func is not None else None
    )
    wrapped_coroutine = (
        quarantine_tool_output(coroutine, session=session, source=source)
        if coroutine is not None
        else None
    )
    return StructuredTool.from_function(
        func=wrapped_func, coroutine=wrapped_coroutine, **structured_tool_kwargs
    )
