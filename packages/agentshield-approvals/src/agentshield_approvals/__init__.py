"""Agent Shield approval service: cryptographic, single-use,
argument-and-resource-bound human-approval receipts, a pending-approval
queue, and consequence-based approval tiering.
"""

from agentshield_approvals.nonce_store import InMemoryNonceStore, NonceStore, RedisNonceStore
from agentshield_approvals.queue import (
    ApprovalStatus,
    InMemoryPendingApprovalQueue,
    PendingApproval,
    PendingApprovalQueue,
    RedisPendingApprovalQueue,
)
from agentshield_approvals.receipt import Receipt, ReceiptPayload, digest_arguments, sign_receipt
from agentshield_approvals.service import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    ApprovalService,
)
from agentshield_approvals.tiering import ApprovalTier, ConsequenceTieringPolicy, TierRule
from agentshield_approvals.verify import VerificationResult, verify_receipt_offline

__all__ = [
    "NonceStore",
    "InMemoryNonceStore",
    "RedisNonceStore",
    "ApprovalStatus",
    "PendingApproval",
    "PendingApprovalQueue",
    "InMemoryPendingApprovalQueue",
    "RedisPendingApprovalQueue",
    "Receipt",
    "ReceiptPayload",
    "digest_arguments",
    "sign_receipt",
    "ApprovalService",
    "ApprovalNotFoundError",
    "ApprovalAlreadyResolvedError",
    "ApprovalTier",
    "ConsequenceTieringPolicy",
    "TierRule",
    "verify_receipt_offline",
    "VerificationResult",
]
