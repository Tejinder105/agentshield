from __future__ import annotations

import json

import pytest
from agentshield_approvals.queue import InMemoryPendingApprovalQueue, PendingApproval
from agentshield_console_api.sse import approval_queue_events, approval_to_dict, format_sse_event

pytestmark = pytest.mark.asyncio


async def test_format_sse_event_without_an_event_name() -> None:
    frame = format_sse_event({"a": 1})
    assert frame == 'data: {"a": 1}\n\n'


async def test_format_sse_event_with_an_event_name() -> None:
    frame = format_sse_event([1, 2, 3], event="snapshot")
    lines = frame.splitlines()
    assert lines[0] == "event: snapshot"
    assert json.loads(lines[1].removeprefix("data: ")) == [1, 2, 3]
    assert frame.endswith("\n\n")


async def test_approval_to_dict_includes_full_arguments() -> None:
    approval = PendingApproval.new(
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"to_account": "acct-1", "amount_usd": 1000},
        resource_version=3,
    )
    rendered = approval_to_dict(approval)
    assert rendered["arguments"] == {"to_account": "acct-1", "amount_usd": 1000}
    assert rendered["status"] == "pending"
    assert rendered["request_id"] == approval.request_id


async def test_approval_queue_events_yields_once_immediately_even_when_empty() -> None:
    queue = InMemoryPendingApprovalQueue()
    frames = [frame async for frame in approval_queue_events(queue, max_iterations=1)]
    assert len(frames) == 1
    assert "event: snapshot" in frames[0]
    assert json.loads(frames[0].splitlines()[1].removeprefix("data: ")) == []


async def test_approval_queue_events_yields_again_only_when_membership_changes() -> None:
    queue = InMemoryPendingApprovalQueue()
    approval = PendingApproval.new(session_id="s1", tool_name="t", arguments={}, resource_version=0)

    async def _enqueue_after_first_iteration() -> None:
        await queue.enqueue(approval)

    frames: list[str] = []
    iteration = 0
    async for frame in approval_queue_events(queue, max_iterations=3, poll_interval_seconds=0.0):
        frames.append(frame)
        iteration += 1
        if iteration == 1:
            await _enqueue_after_first_iteration()

    # Iteration 1: empty snapshot. Iteration 2: membership changed (the
    # enqueue), new snapshot. Iteration 3: unchanged, no new snapshot.
    assert len(frames) == 2
    assert json.loads(frames[0].splitlines()[1].removeprefix("data: ")) == []
    second_payload = json.loads(frames[1].splitlines()[1].removeprefix("data: "))
    assert len(second_payload) == 1
    assert second_payload[0]["request_id"] == approval.request_id
