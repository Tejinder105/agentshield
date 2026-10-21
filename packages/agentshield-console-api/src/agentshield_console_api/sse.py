"""Server-Sent Events formatting and the live approval-queue stream.

Kept framework-agnostic (no FastAPI/Starlette import) so `format_sse_event`
and `approval_queue_events` are each independently unit-testable without
spinning up an ASGI test client; `app.py` wires `approval_queue_events`
into a `StreamingResponse` with `media_type="text/event-stream"`.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

from agentshield_approvals.queue import PendingApproval, PendingApprovalQueue


def format_sse_event(data: Any, *, event: str | None = None) -> str:
    """One Server-Sent Event frame: an optional `event: <name>` line
    followed by `data: <json>`, terminated by the blank line the SSE wire
    format requires between events.
    """
    lines = []
    if event is not None:
        lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data)}")
    return "\n".join(lines) + "\n\n"


def approval_to_dict(approval: PendingApproval) -> dict[str, Any]:
    """The console's full-argument-display view of one pending approval --
    deliberately includes every original tool argument, never a truncated
    or redacted summary, per the plan's "live approval queue ... with full
    argument display".
    """
    return {
        "request_id": approval.request_id,
        "session_id": approval.session_id,
        "tool_name": approval.tool_name,
        "arguments": approval.arguments,
        "resource_version": approval.resource_version,
        "requested_at": approval.requested_at,
        "status": approval.status.value,
    }


async def approval_queue_events(
    queue: PendingApprovalQueue,
    *,
    poll_interval_seconds: float = 1.0,
    max_iterations: int | None = None,
) -> AsyncIterator[str]:
    """Yield a `snapshot` SSE event listing every currently-pending
    approval, once immediately (so a client knows the stream is live even
    if the queue happens to be empty right now) and again every time the
    set of pending request ids changes thereafter.

    Polls `queue.list_pending()` rather than subscribing to a push-based
    change feed: `PendingApprovalQueue` (in-memory or Redis-backed) has no
    such feed today, and polling a small, bounded queue every second or so
    is a deliberately simple, fully adequate choice for an approval
    workflow whose human-timescale latency budget is minutes, not
    milliseconds.

    `max_iterations` exists purely for tests -- production callers never
    pass it, and the generator otherwise runs until the ASGI server
    cancels this coroutine on client disconnect.
    """
    last_ids: frozenset[str] | None = None
    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        pending = await queue.list_pending()
        current_ids = frozenset(a.request_id for a in pending)
        if current_ids != last_ids:
            yield format_sse_event([approval_to_dict(a) for a in pending], event="snapshot")
            last_ids = current_ids
        iterations += 1
        if max_iterations is not None and iterations >= max_iterations:
            break
        await asyncio.sleep(poll_interval_seconds)
