"""`ApprovalService` ties together tiering, the pending queue, receipt
signing, and single-use nonce enforcement into the one object a gateway
(or a console) actually talks to.

`ApprovalService.verify` is written to satisfy
`agentshield_gateway.boundaries.ReceiptVerifier`'s structural `Protocol`
(an async `verify(receipt, *, session_id, tool_name, arguments) -> bool`)
without this package importing or depending on `agentshield-gateway` at
all -- see `agentshield_approvals.tiering` for why that one-directional
(here: absent) dependency is deliberate.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentshield_approvals.nonce_store import NonceStore
from agentshield_approvals.queue import ApprovalStatus, PendingApproval, PendingApprovalQueue
from agentshield_approvals.receipt import Receipt, sign_receipt
from agentshield_approvals.verify import verify_receipt_offline


class ApprovalNotFoundError(KeyError):
    pass


class ApprovalAlreadyResolvedError(ValueError):
    pass


@dataclass(slots=True)
class ApprovalService:
    signing_key: Ed25519PrivateKey
    public_key_hex: str
    queue: PendingApprovalQueue
    nonce_store: NonceStore
    receipt_ttl_seconds: float = 300.0

    async def request_approval(
        self, *, session_id: str, tool_name: str, arguments: dict[str, Any], resource_version: int
    ) -> PendingApproval:
        approval = PendingApproval.new(
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            resource_version=resource_version,
        )
        await self.queue.enqueue(approval)
        return approval

    async def approve(self, request_id: str, *, nonce: str) -> Receipt:
        """Mint a `Receipt` bound to exactly the pending request's
        arguments and resource version, and mark it approved.

        `nonce` is accepted as a parameter (rather than generated here)
        so callers can supply one that is independently auditable (e.g.
        derived from the approver's own session), but a fresh random one
        is just as valid -- the only hard requirement is that it has
        never been claimed before, which `ApprovalService.verify` enforces
        at redemption time, not at mint time.
        """
        approval = await self._get_pending_or_raise(request_id)
        receipt = sign_receipt(
            self.signing_key,
            session_id=approval.session_id,
            tool_name=approval.tool_name,
            arguments=approval.arguments,
            resource_version=approval.resource_version,
            nonce=nonce,
            ttl_seconds=self.receipt_ttl_seconds,
        )
        approval.status = ApprovalStatus.APPROVED
        approval.receipt = receipt
        await self.queue.update(approval)
        return receipt

    async def deny(self, request_id: str) -> PendingApproval:
        approval = await self._get_pending_or_raise(request_id)
        approval.status = ApprovalStatus.DENIED
        await self.queue.update(approval)
        return approval

    async def drain_pending(self) -> list[PendingApproval]:
        """Mark every still-pending approval as expired and return them.

        Called by the revocation kill switch (see `agentshield-revocation`)
        so that an approval requested just before an incident, but not yet
        acted on by a human, cannot be approved and redeemed after
        containment has begun.
        """
        pending = await self.queue.list_pending()
        for approval in pending:
            approval.status = ApprovalStatus.EXPIRED
            await self.queue.update(approval)
        return pending

    async def verify(
        self,
        receipt: Any,
        *,
        session_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        resource_version: int | None = None,
    ) -> bool:
        """Full redemption check: offline binding/expiry/signature
        verification, *then* an atomic single-use nonce claim.

        The nonce is claimed only after every other check passes, so a
        receipt rejected for any other reason (wrong session, expired,
        bad signature) never burns its nonce -- only a receipt that was
        actually valid, and is now being spent, consumes it.
        """
        if not isinstance(receipt, Receipt):
            return False
        result = verify_receipt_offline(
            self.public_key_hex,
            receipt,
            session_id=session_id,
            tool_name=tool_name,
            arguments=arguments,
            now=int(time.time()),
            resource_version=resource_version,
        )
        if not result.ok:
            return False
        remaining_ttl = max(1.0, receipt.payload.exp - time.time())
        return await self.nonce_store.claim(receipt.payload.nonce, ttl_seconds=remaining_ttl)

    async def _get_pending_or_raise(self, request_id: str) -> PendingApproval:
        approval = await self.queue.get(request_id)
        if approval is None:
            raise ApprovalNotFoundError(request_id)
        if approval.status is not ApprovalStatus.PENDING:
            raise ApprovalAlreadyResolvedError(
                f"approval {request_id!r} was already resolved as {approval.status.value!r}"
            )
        return approval
