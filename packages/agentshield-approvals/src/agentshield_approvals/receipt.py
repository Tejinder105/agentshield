"""Cryptographic approval receipts.

A receipt is bound to exactly `{session, tool, arg_digest, resource_version,
nonce, exp}`, signed with Ed25519, and canonicalized with the same
restricted RFC 8785 encoder the ledger uses -- reusing
`agentshield_ledger.verify.canonical` rather than a second canonicalization
implementation is deliberate: two canonicalizers that happen to agree today
but drift apart later is exactly the kind of bug that would make a validly
signed receipt fail re-verification for reasons that have nothing to do
with tampering.

Binding to `arg_digest` (not the raw arguments) means a human approves the
digest of exactly what they were shown; binding to `resource_version` is
what defeats the classic "approve, then race the state to invalidate
the approval's premise before it's redeemed" attack -- see the module
docstring in `agentshield_approvals.verify` for how that check is used.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentshield_ledger.verify.canonical import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def digest_arguments(arguments: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical encoding of a tool call's arguments."""
    return hashlib.sha256(canonicalize(arguments)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReceiptPayload:
    session_id: str
    tool_name: str
    arg_digest: str
    resource_version: int
    nonce: str
    exp: int  # unix epoch seconds

    def canonical_bytes(self) -> bytes:
        """The exact bytes the signature covers."""
        return canonicalize(
            {
                "session": self.session_id,
                "tool": self.tool_name,
                "arg_digest": self.arg_digest,
                "resource_version": self.resource_version,
                "nonce": self.nonce,
                "exp": self.exp,
            }
        )

    def is_expired(self, *, now: int | None = None) -> bool:
        current = now if now is not None else int(time.time())
        return current >= self.exp

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "arg_digest": self.arg_digest,
            "resource_version": self.resource_version,
            "nonce": self.nonce,
            "exp": self.exp,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ReceiptPayload:
        return ReceiptPayload(
            session_id=data["session_id"],
            tool_name=data["tool_name"],
            arg_digest=data["arg_digest"],
            resource_version=data["resource_version"],
            nonce=data["nonce"],
            exp=data["exp"],
        )


@dataclass(frozen=True, slots=True)
class Receipt:
    payload: ReceiptPayload
    signature_hex: str

    def to_dict(self) -> dict[str, Any]:
        return {"payload": self.payload.to_dict(), "signature": self.signature_hex}

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Receipt:
        return Receipt(
            payload=ReceiptPayload.from_dict(data["payload"]), signature_hex=data["signature"]
        )


def sign_receipt(
    private_key: Ed25519PrivateKey,
    *,
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    resource_version: int,
    nonce: str,
    ttl_seconds: float,
) -> Receipt:
    payload = ReceiptPayload(
        session_id=session_id,
        tool_name=tool_name,
        arg_digest=digest_arguments(arguments),
        resource_version=resource_version,
        nonce=nonce,
        exp=int(time.time() + ttl_seconds),
    )
    signature = private_key.sign(payload.canonical_bytes())
    return Receipt(payload=payload, signature_hex=signature.hex())
