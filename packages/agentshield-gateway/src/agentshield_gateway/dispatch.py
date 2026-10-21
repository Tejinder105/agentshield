"""Dispatching an ALLOWed call to the real tool.

Agent Shield's job ends at the authorization decision. `ToolDispatcher` is
the one, deliberately narrow, seam between "the pipeline said yes" and
"something outside this codebase actually ran the tool" -- the gateway
proxies to the real MCP server or in-process handler through this
interface rather than reimplementing a transport.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol


class ToolDispatcher(Protocol):
    async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute `tool_name` with `arguments` and return its result.

        May raise. The pipeline treats any exception here as "uncertain":
        the call was authorized and attempted, but whether the external
        side effect happened is unknown -- per the threat model, Agent
        Shield cannot undo it either way, so the ledger records the
        ambiguity honestly rather than guessing.
        """
        ...


ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class InMemoryToolDispatcher:
    """A dispatcher backed by plain async callables. Used in tests, and for
    embedding Agent Shield directly in front of in-process tool
    implementations rather than a networked MCP server.
    """

    def __init__(self, handlers: dict[str, ToolHandler] | None = None) -> None:
        self._handlers: dict[str, ToolHandler] = dict(handlers) if handlers else {}

    def register(self, tool_name: str, handler: ToolHandler) -> None:
        self._handlers[tool_name] = handler

    async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = self._handlers.get(tool_name)
        if handler is None:
            raise KeyError(f"no handler registered for tool {tool_name!r}")
        return await handler(arguments)


class HttpToolDispatcher:
    """Forwards an allowed call to a real downstream MCP server reachable
    over plain HTTP. Deliberately the thinnest possible bridge: one POST,
    one JSON body in, one JSON body out. A deployment speaking full MCP
    transport semantics to its downstream server should use the mcp v2
    middleware's `call_next` bridge instead (see
    `agentshield_gateway.mcp_middleware`), which dispatches through the
    real MCP session rather than a side-channel HTTP call.
    """

    def __init__(self, base_url: str, client: Any) -> None:
        self._base_url = base_url.rstrip("/")
        self._client = client  # an httpx.AsyncClient, injected rather than owned

    async def dispatch(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(f"{self._base_url}/tools/{tool_name}", json=arguments)
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            return {"result": result}
        return result
