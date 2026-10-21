"""Offline receipt verification, independent of any pending-approval queue
or nonce store.

This checks everything a receipt's own bytes can prove on their own:
binding (session, tool, arguments, resource version), expiry, and
signature validity. It deliberately does *not* check single-use -- that
requires shared state (a nonce store) an offline auditor does not have,
and is `ApprovalService.verify`'s job, layered on top of this function.
This split means an auditor who only has the pinned public key and a
receipt can independently confirm "this receipt, on its own terms, is
genuine and was for this exact call" without needing to trust or even
contact the approval service at all.

Built entirely on `agentshield_ledger.verify`'s zero-dependency primitives
(`ed25519_pure`, by way of `canonicalize` inside `receipt.py`), so this
check carries the same "no server-side dependency tree required" property
the ledger's own offline verifier does.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentshield_ledger.verify.ed25519_pure import verify as ed25519_verify

from agentshield_approvals.receipt import Receipt, digest_arguments


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str

    def __bool__(self) -> bool:
        return self.ok


def verify_receipt_offline(
    public_key_hex: str,
    receipt: Receipt,
    *,
    session_id: str,
    tool_name: str,
    arguments: Mapping[str, Any],
    now: int,
    resource_version: int | None = None,
) -> VerificationResult:
    if receipt.payload.session_id != session_id:
        return VerificationResult(False, "receipt is bound to a different session")
    if receipt.payload.tool_name != tool_name:
        return VerificationResult(False, "receipt is bound to a different tool")
    if receipt.payload.arg_digest != digest_arguments(arguments):
        return VerificationResult(False, "receipt is bound to different arguments")
    if resource_version is not None and receipt.payload.resource_version != resource_version:
        return VerificationResult(False, "the resource has changed since approval -- stale receipt")
    if receipt.payload.is_expired(now=now):
        return VerificationResult(False, "receipt has expired")

    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(receipt.signature_hex)
    except ValueError:
        return VerificationResult(False, "malformed public key or signature encoding")

    if not ed25519_verify(public_key, receipt.payload.canonical_bytes(), signature):
        return VerificationResult(False, "invalid signature")
    return VerificationResult(True, "ok")
