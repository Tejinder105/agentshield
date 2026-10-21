"""Ed25519 checkpoint signing for the ledger (server-side; uses `cryptography`).

A checkpoint is the operator's signed commitment to a specific Merkle root
at a specific tree size, chained to the previous checkpoint's hash. This is
what later lets `agentshield_ledger.verify` -- or any third party holding
only the public key -- detect a rewrite of history, provided at least one
honestly-published checkpoint predates the rewrite (see
`agentshield_ledger.anchoring` for why *publishing* checkpoints externally
matters, not just signing them).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentshield_ledger.verify.canonical import canonicalize

GENESIS_CHECKPOINT_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class Checkpoint:
    merkle_root_hex: str
    tree_size: int
    prev_checkpoint_hash: str
    timestamp: int  # unix epoch seconds
    signature_hex: str

    def signed_payload(self) -> bytes:
        """The exact bytes the signature covers. Deliberately excludes the
        signature itself, obviously, but also excludes anything not needed
        to pin the checkpoint's meaning -- no free-form metadata that could
        be tampered with without invalidating the signature yet still
        change how the checkpoint is interpreted.
        """
        return canonicalize(
            {
                "merkle_root": self.merkle_root_hex,
                "tree_size": self.tree_size,
                "prev_checkpoint_hash": self.prev_checkpoint_hash,
                "timestamp": self.timestamp,
            }
        )


def sign_checkpoint(
    private_key: Ed25519PrivateKey,
    *,
    merkle_root: bytes,
    tree_size: int,
    prev_checkpoint_hash: str,
    timestamp: int,
) -> Checkpoint:
    unsigned = Checkpoint(
        merkle_root_hex=merkle_root.hex(),
        tree_size=tree_size,
        prev_checkpoint_hash=prev_checkpoint_hash,
        timestamp=timestamp,
        signature_hex="",
    )
    signature = private_key.sign(unsigned.signed_payload())
    return Checkpoint(
        merkle_root_hex=unsigned.merkle_root_hex,
        tree_size=unsigned.tree_size,
        prev_checkpoint_hash=unsigned.prev_checkpoint_hash,
        timestamp=unsigned.timestamp,
        signature_hex=signature.hex(),
    )


def verify_checkpoint(public_key: Ed25519PublicKey, checkpoint: Checkpoint) -> bool:
    """Server-side convenience verifier using `cryptography`. The
    independent, dependency-free verifier an external auditor would
    actually use is `agentshield_ledger.verify.ed25519_pure.verify`; this
    one exists so the service itself can sanity-check a checkpoint (e.g.
    after loading one back from storage) without round-tripping through
    the pure-Python implementation.
    """
    try:
        public_key.verify(bytes.fromhex(checkpoint.signature_hex), checkpoint.signed_payload())
    except Exception:
        return False
    return True


def checkpoint_hash(checkpoint: Checkpoint) -> str:
    """Hash of this checkpoint, used as the next checkpoint's
    `prev_checkpoint_hash`. Must match `verify.cli`'s inline recomputation
    of the same value exactly.
    """
    payload = checkpoint.signed_payload() + bytes.fromhex(checkpoint.signature_hex)
    return hashlib.sha256(payload).hexdigest()
