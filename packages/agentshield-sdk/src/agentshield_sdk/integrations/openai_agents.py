"""Dual-LLM quarantine for the OpenAI Agents SDK.

`shielded_function_tool` is a thin wrapper over `agents.function_tool`:
the real tool implementation is first wrapped with
`agentshield_sdk.toolwrap.quarantine_tool_output`, then handed to
`function_tool` exactly as if it had been written to return a `var_`
token directly. Every `function_tool` keyword argument (`name_override`,
`strict_mode`, `is_enabled`, ...) still works unchanged, since this
function is a strict superset: it only ever intercepts the call
*between* the framework and the real implementation, never the framework
itself.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agents import FunctionTool, function_tool
from agents.tool_guardrails import (
    ToolGuardrailFunctionOutput,
    ToolInputGuardrail,
    ToolInputGuardrailData,
)

from agentshield_sdk.handles import UnknownHandleError
from agentshield_sdk.session import SdkSession
from agentshield_sdk.toolwrap import quarantine_tool_output


def shielded_function_tool(
    fn: Callable[..., Any],
    *,
    session: SdkSession,
    source: str,
    **function_tool_kwargs: Any,
) -> FunctionTool:
    """Build an `agents.FunctionTool` from `fn` whose result the model
    never sees directly -- only a `var_` handle token for it. `source` is
    the provenance label shown in audit explanations (e.g.
    `"tool:read_email#inbox"`); the result is labeled `Label.untrusted()`
    by default (see `SdkSession.quarantine_result`), since the model
    receiving this tool is, by definition, exposed to whatever `fn`
    returns and must treat it as such.
    """
    wrapped = quarantine_tool_output(fn, session=session, source=source)
    tool = function_tool(wrapped, **function_tool_kwargs)
    existing = tool.tool_input_guardrails or []
    tool.tool_input_guardrails = [*existing, build_handle_integrity_guardrail(session)]
    return tool


def build_handle_integrity_guardrail(session: SdkSession) -> ToolInputGuardrail[Any]:
    """A defense-in-depth `ToolInputGuardrail` that proactively rejects a
    call whose arguments reference a `var_` token this session's
    `VarStore` never issued, *before* the real tool implementation ever
    runs -- rather than relying solely on `quarantine_tool_output`'s own
    `UnknownHandleError` (which still fires regardless, this is strictly
    additional, earlier, and framework-visible rejection).
    """

    async def _check(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        try:
            raw_arguments = json.loads(data.context.tool_arguments)
        except (json.JSONDecodeError, TypeError):
            return ToolGuardrailFunctionOutput.allow()
        try:
            session.var_store.resolve_in(raw_arguments)
        except UnknownHandleError as exc:
            return ToolGuardrailFunctionOutput.reject_content(
                message=f"rejected: argument references an unknown var_ handle ({exc})",
                output_info={"reason": "unknown_var_handle"},
            )
        return ToolGuardrailFunctionOutput.allow()

    return ToolInputGuardrail(guardrail_function=_check, name="agent_shield_handle_integrity")
