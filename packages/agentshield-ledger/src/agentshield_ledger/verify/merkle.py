"""A Merkle tree following RFC 6962's domain separation, with lone nodes
promoted rather than duplicated.

RFC 6962 defines leaf hashes as `H(0x00 || leaf)` and internal node hashes
as `H(0x01 || left || right)`. That domain separation alone stops a leaf
from ever being mistaken for an internal node. Separately, naive
implementations that pair an unpaired trailing node with a duplicate of
itself make `[a, b, c]` and `[a, b, c, c]` hash to the same root --
catalogued as CVE-2012-2459. This implementation instead promotes an
unpaired node unchanged to the next level, closing that hole.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def empty_root() -> bytes:
    """RFC 6962: the hash of an empty tree is SHA-256 of the empty string."""
    return hashlib.sha256(b"").digest()


def _next_level(level: tuple[bytes, ...]) -> tuple[bytes, ...]:
    next_level: list[bytes] = []
    i = 0
    while i < len(level):
        if i + 1 < len(level):
            next_level.append(node_hash(level[i], level[i + 1]))
            i += 2
        else:
            # Promote the lone node unchanged. Do NOT pair it with a copy
            # of itself -- that is exactly the CVE-2012-2459 construction.
            next_level.append(level[i])
            i += 1
    return tuple(next_level)


@dataclass(frozen=True, slots=True)
class MerkleTree:
    """An immutable Merkle tree over a fixed, ordered list of leaves."""

    levels: tuple[tuple[bytes, ...], ...]  # levels[0] is leaf-hashed data, levels[-1] is (root,)
    size: int  # number of real leaves; 0 for the empty tree (distinct from a 1-leaf tree)

    @staticmethod
    def build(raw_entries: list[bytes]) -> MerkleTree:
        if not raw_entries:
            return MerkleTree(levels=((empty_root(),),), size=0)
        level = tuple(leaf_hash(e) for e in raw_entries)
        levels: list[tuple[bytes, ...]] = [level]
        while len(level) > 1:
            level = _next_level(level)
            levels.append(level)
        return MerkleTree(levels=tuple(levels), size=len(raw_entries))

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def inclusion_proof(self, index: int) -> list[bytes]:
        """Sibling hashes from `index`'s leaf up to the root.

        A promoted lone node contributes *no* sibling hash at that level --
        there is nothing to pair it with -- so the proof list's length can
        be shorter than `ceil(log2(size))` for indices near a promotion.
        `verify_inclusion` reconstructs the same promotion decisions from
        `size` alone, so this asymmetry is handled identically on both
        sides.
        """
        if not (0 <= index < self.size):
            raise IndexError(index)
        proof: list[bytes] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                if sibling_idx < len(level):
                    proof.append(level[sibling_idx])
                # else: promoted at this level; no sibling to record.
            else:
                proof.append(level[idx - 1])
            idx //= 2
        return proof


def verify_inclusion(
    root: bytes, size: int, index: int, leaf_data: bytes, proof: list[bytes]
) -> bool:
    """Recompute the root from `leaf_data` and `proof` alone (no access to
    the full tree) and compare against `root`. This is the logarithmic,
    "I only need this one entry" verification path; `cli.py`'s full
    recomputation is the alternative, "I have the whole export anyway"
    path used for a complete audit.
    """
    if not (0 <= index < size):
        return False
    current = leaf_hash(leaf_data)
    idx = index
    level_size = size
    proof_iter = iter(proof)
    while level_size > 1:
        has_sibling_on_right = idx % 2 == 0 and idx + 1 < level_size
        is_promoted = idx % 2 == 0 and idx + 1 >= level_size
        if is_promoted:
            pass  # current carries forward unchanged, no proof hash consumed
        elif has_sibling_on_right:
            try:
                sibling = next(proof_iter)
            except StopIteration:
                return False
            current = node_hash(current, sibling)
        else:
            try:
                sibling = next(proof_iter)
            except StopIteration:
                return False
            current = node_hash(sibling, current)
        idx //= 2
        level_size = (level_size + 1) // 2
    return current == root
