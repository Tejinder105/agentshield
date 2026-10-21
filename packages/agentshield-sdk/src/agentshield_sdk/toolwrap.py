"""`quarantine_tool_output`: the one piece of logic both framework
integrations (`agentshield_sdk.integrations.openai_agents` and
`agentshield_sdk.integrations.langchain`) are thin adapters over.

Deliberately framework-agnostic: it wraps a plain Python callable (sync or
async) and knows nothing about `agents.function_tool` or
`langchain_core.tools.StructuredTool` at all. Both integrations call this,
then hand the wrapped callable to their own framework's native
tool-building function. That split keeps the actual security-relevant
logic in one place that is fully unit-testable without installing either
(heavy, fast-moving) framework, and keeps each framework-specific adapter
small enough to re-verify quickly if that framework's API shifts.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable
from typing import Any, overload

from agentshield_sdk.session import SdkSession


@overload
def quarantine_tool_output(
    fn: Callable[..., Awaitable[Any]],
    *,
    session: SdkSession,
    source: str,
) -> Callable[..., Awaitable[str]]: ...


@overload
def quarantine_tool_output(
    fn: Callable[..., Any],
    *,
    session: SdkSession,
    source: str,
) -> Callable[..., str]: ...


def quarantine_tool_output(
    fn: Callable[..., Any],
    *,
    session: SdkSession,
    source: str,
) -> Callable[..., Awaitable[str]] | Callable[..., str]:
    """Wrap a real tool implementation `fn` so that:

    1. Before `fn` runs, every keyword argument is passed through
       `session.var_store.resolve_in` -- any `var_` token the planner
       passed in is dereferenced to its real, still-tainted value right
       here, at the last possible moment before dispatch ("orchestrator-
       side dereferencing at dispatch").
    2. `fn`'s *real* return value is never returned to the caller.
       Instead it is quarantined (`session.quarantine_result`) and only
       the resulting `var_` handle's token string comes back -- so a
       framework's own schema introspection of the *wrapped* function
       still sees a plain string return, and the planner LLM that
       eventually receives this tool's result only ever sees `"var_N"`.

    `functools.wraps` preserves `fn`'s name, docstring, and signature
    (via `__wrapped__`), which both `agents.function_tool` and
    `langchain_core.tools.StructuredTool.from_function` rely on via
    `inspect.signature` to build the tool's *input* JSON schema -- that
    schema is unaffected by this wrapping; only the *output* type changes
    from "whatever `fn` returns" to "a `var_` token string".
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> str:
            # Both forms matter: `agents.function_tool`'s generated
            # `on_invoke_tool` calls the wrapped function with its
            # arguments *positionally*, matched by the original
            # signature's parameter order, while
            # `langchain_core.tools.StructuredTool` calls it with
            # *keyword* arguments -- resolving only one of the two would
            # silently skip dereferencing for whichever framework uses
            # the other calling convention.
            resolved_args = tuple(session.var_store.resolve_in(a) for a in args)
            resolved_kwargs = {k: session.var_store.resolve_in(v) for k, v in kwargs.items()}
            result = await fn(*resolved_args, **resolved_kwargs)
            handle = session.quarantine_result(result, source=source)
            return handle.token

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> str:
        resolved_args = tuple(session.var_store.resolve_in(a) for a in args)
        resolved_kwargs = {k: session.var_store.resolve_in(v) for k, v in kwargs.items()}
        result = fn(*resolved_args, **resolved_kwargs)
        handle = session.quarantine_result(result, source=source)
        return handle.token

    return sync_wrapper
