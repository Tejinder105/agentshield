"""The pending-approval queue: tool calls awaiting a human decision.

`PendingApproval` is the queue's record of one call that reached pipeline
step 4's approval-tiering extension (see `agentshield_approvals.tiering`)
and is now waiting for a human to approve or deny it, before a `Receipt`
can be minted for it (see `agentshield_approvals.service`).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from agentshield_approvals.receipt import Receipt


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(slots=True)
class PendingApproval:
    request_id: str
    session_id: str
    tool_name: str
    arguments: dict[str, Any]
    resource_version: int
    requested_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    receipt: Receipt | None = None

    @staticmethod
    def new(
        *, session_id: str, tool_name: str, arguments: dict[str, Any], resource_version: int
    ) -> PendingApproval:
        return PendingApproval(
            request_id=str(uuid.uuid4()),
            session_id=session_id,
            tool_name=tool_name,
            arguments=dict(arguments),
            resource_version=resource_version,
            requested_at=time.time(),
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "request_id": self.request_id,
                "session_id": self.session_id,
                "tool_name": self.tool_name,
                "arguments": self.arguments,
                "resource_version": self.resource_version,
                "requested_at": self.requested_at,
                "status": self.status.value,
                "receipt": self.receipt.to_dict() if self.receipt is not None else None,
            }
        )

    @staticmethod
    def from_json(data: str) -> PendingApproval:
        raw = json.loads(data)
        return PendingApproval(
            request_id=raw["request_id"],
            session_id=raw["session_id"],
            tool_name=raw["tool_name"],
            arguments=raw["arguments"],
            resource_version=raw["resource_version"],
            requested_at=raw["requested_at"],
            status=ApprovalStatus(raw["status"]),
            receipt=Receipt.from_dict(raw["receipt"]) if raw["receipt"] is not None else None,
        )


class PendingApprovalQueue(Protocol):
    async def enqueue(self, approval: PendingApproval) -> None: ...
    async def get(self, request_id: str) -> PendingApproval | None: ...
    async def update(self, approval: PendingApproval) -> None: ...
    async def list_pending(self) -> list[PendingApproval]:
        """Every approval still in `ApprovalStatus.PENDING`. Used by the
        revocation kill switch to drain the queue on an incident -- see
        `ApprovalService.drain_pending`.
        """
        ...


class InMemoryPendingApprovalQueue:
    def __init__(self) -> None:
        self._store: dict[str, PendingApproval] = {}

    async def enqueue(self, approval: PendingApproval) -> None:
        self._store[approval.request_id] = approval

    async def get(self, request_id: str) -> PendingApproval | None:
        return self._store.get(request_id)

    async def update(self, approval: PendingApproval) -> None:
        self._store[approval.request_id] = approval

    async def list_pending(self) -> list[PendingApproval]:
        return [a for a in self._store.values() if a.status is ApprovalStatus.PENDING]


class RedisPendingApprovalQueue:
    """Each approval is a JSON blob under its own key, plus a Redis set
    tracking which request ids are currently pending -- `list_pending` is
    therefore O(pending), not a full key-space scan, which matters because
    it is on the critical path of the revocation kill switch.
    """

    def __init__(self, redis_client: Any, *, key_prefix: str = "agentshield:approval:") -> None:
        self._redis = redis_client
        self._prefix = key_prefix
        self._pending_set_key = f"{key_prefix}pending"

    def _key(self, request_id: str) -> str:
        return f"{self._prefix}{request_id}"

    async def enqueue(self, approval: PendingApproval) -> None:
        await self._redis.set(self._key(approval.request_id), approval.to_json())
        await self._sync_pending_membership(approval)

    async def get(self, request_id: str) -> PendingApproval | None:
        raw = await self._redis.get(self._key(request_id))
        if raw is None:
            return None
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        return PendingApproval.from_json(text)

    async def update(self, approval: PendingApproval) -> None:
        await self._redis.set(self._key(approval.request_id), approval.to_json())
        await self._sync_pending_membership(approval)

    async def list_pending(self) -> list[PendingApproval]:
        raw_ids = await self._redis.smembers(self._pending_set_key)
        approvals: list[PendingApproval] = []
        for raw_id in raw_ids:
            request_id = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else raw_id
            approval = await self.get(request_id)
            if approval is not None:
                approvals.append(approval)
        return approvals

    async def _sync_pending_membership(self, approval: PendingApproval) -> None:
        if approval.status is ApprovalStatus.PENDING:
            await self._redis.sadd(self._pending_set_key, approval.request_id)
        else:
            await self._redis.srem(self._pending_set_key, approval.request_id)
