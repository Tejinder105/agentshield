"""The real `tools/call` interception point, as an `mcp` v2 server-tier
middleware.

`mcp` v2's lowlevel `Server` runs every inbound message through a chain of
`ServerMiddleware` objects (`server.middleware.append(...)`) before it
reaches the method-specific handler. `AgentShieldMiddleware` is one such
middleware: for every `tools/call` message, it runs the Agent Shield
decision pipeline *before* `call_next` is allowed to reach the real tool
implementation, and on denial, short-circuits with an error `CallToolResult`
instead of calling `call_next` at all. Every other method (`tools/list`,
`prompts/get`, pings, ...) passes straight through unexamined.
"""

from __future__ import annotations

from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerMiddleware, ServerRequestContext
from mcp.types import CallToolResult, TextContent

from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, OutcomeStatus, ToolCallRequest
from agentshield_gateway.session import SessionStore


class _CallNextDispatcher:
    """Bridges `ToolDispatcher.dispatch(tool_name, arguments)` -- the shape
    the pipeline's step 8 expects -- to `call_next(ctx)`, which is how mcp
    v2 actually invokes the next handler in the chain (ultimately the real
    tool implementation). This is what lets the *same* `DecisionPipeline`
    serve both the FastAPI HTTP surface (`agentshield_gateway.app`, which
    dispatches via `ToolDispatcher.dispatch` against a real downstream
    client) and this in-process mcp v2 server, without the pipeline itself
    knowing which transport it is running behind.
    """

    def __init__(self, ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> None:
        self._ctx = ctx
        self._call_next = call_next
        self.last_result: HandlerResult | None = None

    async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:  # noqa: ARG002
        result = await self._call_next(self._ctx)
        self.last_result = result
        if isinstance(result, CallToolResult):
            if result.is_error:
                raise RuntimeError(f"downstream tool {tool_name!r} reported an error result")
            return {
                "content": [content.model_dump(mode="json") for content in (result.content or [])]
            }
        return {"result": repr(result)}


class AgentShieldMiddleware(ServerMiddleware[Any]):
    def __init__(
        self,
        *,
        pipeline: DecisionPipeline,
        sessions: SessionStore,
        default_tools: list[dict[str, Any]],
    ) -> None:
        """`default_tools` is pinned for any session the middleware has not
        seen before -- i.e. this middleware assumes a single, fixed
        downstream tool list rather than per-session `tools/list` pinning.
        A deployment with per-session tool discovery should instead call
        `PinnedToolSet.pin(...)` explicitly once per session (as the
        FastAPI surface's `POST /sessions` endpoint does) before any
        `tools/call` for that session reaches this middleware.
        """
        self._pipeline = pipeline
        self._sessions = sessions
        self._default_tools = default_tools

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        if ctx.method != "tools/call" or not ctx.params:
            return await call_next(ctx)

        tool_name = ctx.params.get("name")
        if not isinstance(tool_name, str):
            return await call_next(ctx)
        arguments_raw = ctx.params.get("arguments")
        arguments: dict[str, Any] = dict(arguments_raw) if isinstance(arguments_raw, dict) else {}

        session_id = self._resolve_session_id(ctx)
        session = self._sessions.get_or_create(session_id)
        if not session.pinned_tools.digests:
            from agentshield_gateway.schema_pinning import PinnedToolSet

            session.pinned_tools = PinnedToolSet.pin(self._default_tools)

        current_schema = next((t for t in self._default_tools if t.get("name") == tool_name), None)

        dispatcher: ToolDispatcher = _CallNextDispatcher(ctx=ctx, call_next=call_next)
        call_request = ToolCallRequest(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            raw_context={"principal": session_id},
            current_tool_schema=current_schema,
        )
        outcome = await self._pipeline.evaluate_and_dispatch(call_request, session, dispatcher)

        if outcome.status is OutcomeStatus.DISPATCHED:
            assert isinstance(dispatcher, _CallNextDispatcher)
            if dispatcher.last_result is not None:
                return dispatcher.last_result

        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=f"[agent-shield:{outcome.decision.stage}] {outcome.decision.reason}",
                )
            ],
            is_error=True,
        )

    def _resolve_session_id(self, ctx: ServerRequestContext[Any, Any]) -> str:
        """Session/principal identity resolution here is intentionally
        minimal: a stable id derived from the underlying `ServerSession`
        object. Production deployments should instead populate `ctx.meta`
        from a verified authentication layer (mTLS, signed bearer token)
        upstream of this middleware, and resolve the real identity from
        that. This is a deliberate, documented scope boundary -- see
        docs/threat-model.md's non-goals -- not an oversight.
        """
        return f"mcp-session-{id(ctx.session)}"
