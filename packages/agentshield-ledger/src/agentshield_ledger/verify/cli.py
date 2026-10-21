"""Standalone, zero-dependency offline verifier for an Agent Shield ledger
export.

Run as::

    python -m agentshield_ledger.verify.cli export.json --public-key <hex>

or, if the package is installed, via the `agentshield-verify` console
script. This module -- together with `canonical.py`, `hashchain.py`,
`merkle.py`, and `ed25519_pure.py` in this same `verify` subpackage --
imports nothing beyond the Python standard library, by design: see the
subpackage docstring in `verify/__init__.py`.

The checkpoint-chaining hash (`sha256(signed_payload + signature)`) is
intentionally recomputed here with raw `hashlib`, rather than imported from
`agentshield_ledger.checkpoint`, because that module depends on
`cryptography`. Duplicating five lines of hashing logic is the price of
keeping this file's dependency graph at zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from agentshield_ledger.verify.canonical import canonicalize
from agentshield_ledger.verify.ed25519_pure import verify as ed25519_verify
from agentshield_ledger.verify.hashchain import GENESIS_HASH, compute_entry_hash
from agentshield_ledger.verify.merkle import MerkleTree

GENESIS_CHECKPOINT_HASH = "0" * 64


class VerificationFailure(Exception):
    """Raised the moment any check fails. The ledger is not trustworthy as
    presented if this is ever raised; there is no "partial trust" outcome.
    """


def verify_hash_chain(entries: list[dict[str, Any]]) -> None:
    expected_prev = GENESIS_HASH
    for e in entries:
        if e["prev_hash"] != expected_prev:
            raise VerificationFailure(f"seq {e['seq']}: prev_hash mismatch (chain broken)")
        if compute_entry_hash(e["prev_hash"], e["entry"]) != e["entry_hash"]:
            raise VerificationFailure(f"seq {e['seq']}: entry_hash does not match recomputed hash")
        expected_prev = e["entry_hash"]


def _checkpoint_signed_payload(cp: dict[str, Any]) -> bytes:
    return canonicalize(
        {
            "merkle_root": cp["merkle_root"],
            "tree_size": cp["tree_size"],
            "prev_checkpoint_hash": cp["prev_checkpoint_hash"],
            "timestamp": cp["timestamp"],
        }
    )


def verify_checkpoints(
    entries: list[dict[str, Any]], checkpoints: list[dict[str, Any]], public_key_hex: str
) -> None:
    public_key = bytes.fromhex(public_key_hex)
    expected_prev_checkpoint_hash = GENESIS_CHECKPOINT_HASH

    for cp in checkpoints:
        leaves = [canonicalize(e["entry"]) for e in entries[: cp["tree_size"]]]
        tree = MerkleTree.build(leaves)
        if tree.root.hex() != cp["merkle_root"]:
            raise VerificationFailure(
                f"checkpoint at tree_size={cp['tree_size']}: recomputed Merkle root mismatch"
            )
        if cp["prev_checkpoint_hash"] != expected_prev_checkpoint_hash:
            raise VerificationFailure(
                f"checkpoint at tree_size={cp['tree_size']}: checkpoint chain broken"
            )

        payload = _checkpoint_signed_payload(cp)
        signature = bytes.fromhex(cp["signature"])
        if not ed25519_verify(public_key, payload, signature):
            raise VerificationFailure(f"checkpoint at tree_size={cp['tree_size']}: bad signature")

        expected_prev_checkpoint_hash = hashlib.sha256(payload + signature).hexdigest()


def verify_export(export: dict[str, Any], public_key_hex: str) -> None:
    """Full offline verification: the hash chain is internally consistent,
    every checkpoint's Merkle root matches a from-scratch recomputation
    over the entries it claims to cover, the checkpoint chain itself is
    unbroken, and every checkpoint signature verifies against the pinned
    public key.
    """
    verify_hash_chain(export["entries"])
    verify_checkpoints(export["entries"], export["checkpoints"], public_key_hex)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentshield-verify",
        description="Offline, dependency-free verification of an Agent Shield ledger export.",
    )
    parser.add_argument("export_path", type=Path, help="Path to a ledger export JSON file")
    parser.add_argument(
        "--public-key",
        required=True,
        help="Hex-encoded Ed25519 public key for the checkpoint signer, pinned out-of-band",
    )
    args = parser.parse_args(argv)

    export = json.loads(args.export_path.read_text(encoding="utf-8"))
    try:
        verify_export(export, args.public_key)
    except VerificationFailure as exc:
        print(f"TAMPER DETECTED: {exc}", file=sys.stderr)
        return 1
    except (KeyError, ValueError) as exc:
        print(f"MALFORMED EXPORT: {exc}", file=sys.stderr)
        return 2

    entry_count = len(export["entries"])
    checkpoint_count = len(export["checkpoints"])
    print(f"OK: {entry_count} entries, {checkpoint_count} checkpoints verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
