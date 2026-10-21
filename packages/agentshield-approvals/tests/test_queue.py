from __future__ import annotations

import pytest
from agentshield_approvals.queue import (
    ApprovalStatus,
    InMemoryPendingApprovalQueue,
    PendingApproval,
    RedisPendingApprovalQueue,
)
from fakeredis.aioredis import FakeRedis

pytestmark = pytest.mark.asyncio


async def test_in_memory_enqueue_and_get_round_trip() -> None:
    queue = InMemoryPendingApprovalQueue()
    approval = PendingApproval.new(
        session_id="s1", tool_name="send_email", arguments={"to": "alice"}, resource_version=1
    )
    await queue.enqueue(approval)
    fetched = await queue.get(approval.request_id)
    assert fetched is not None
    assert fetched.tool_name == "send_email"
    assert fetched.status is ApprovalStatus.PENDING


async def test_in_memory_get_of_unknown_id_is_none() -> None:
    queue = InMemoryPendingApprovalQueue()
    assert await queue.get("does-not-exist") is None


async def test_in_memory_list_pending_excludes_resolved() -> None:
    queue = InMemoryPendingApprovalQueue()
    pending = PendingApproval.new(session_id="s1", tool_name="t", arguments={}, resource_version=0)
    resolved = PendingApproval.new(session_id="s1", tool_name="t", arguments={}, resource_version=0)
    resolved.status = ApprovalStatus.DENIED
    await queue.enqueue(pending)
    await queue.enqueue(resolved)
    result = await queue.list_pending()
    assert [a.request_id for a in result] == [pending.request_id]


async def test_pending_approval_json_round_trips() -> None:
    approval = PendingApproval.new(
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice", "n": 1},
        resource_version=3,
    )
    restored = PendingApproval.from_json(approval.to_json())
    assert restored == approval


async def test_redis_enqueue_and_get_round_trip() -> None:
    queue = RedisPendingApprovalQueue(FakeRedis())
    approval = PendingApproval.new(
        session_id="s1", tool_name="send_email", arguments={"to": "alice"}, resource_version=1
    )
    await queue.enqueue(approval)
    fetched = await queue.get(approval.request_id)
    assert fetched == approval


async def test_redis_list_pending_tracks_membership_as_status_changes() -> None:
    queue = RedisPendingApprovalQueue(FakeRedis())
    approval = PendingApproval.new(session_id="s1", tool_name="t", arguments={}, resource_version=0)
    await queue.enqueue(approval)
    assert len(await queue.list_pending()) == 1

    approval.status = ApprovalStatus.APPROVED
    await queue.update(approval)
    assert await queue.list_pending() == []
    # The resolved record itself is still retrievable, just no longer "pending".
    refreshed = await queue.get(approval.request_id)
    assert refreshed is not None
    assert refreshed.status is ApprovalStatus.APPROVED


async def test_redis_get_of_unknown_id_is_none() -> None:
    queue = RedisPendingApprovalQueue(FakeRedis())
    assert await queue.get("nope") is None
