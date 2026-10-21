"""Integrity/confidentiality label lattice.

This module is the mathematical foundation of Agent Shield's information-flow
control. Every claim the system makes about "an untrusted value cannot flow
into a privileged tool call" rests on `Label.join` actually being a lattice
join: associative, commutative, idempotent, and monotonic with respect to the
partial order. Those laws are checked with hypothesis property tests in
`tests/test_labels.py` -- if they ever fail, the information-flow argument for
the rest of the system is unsound, not just buggy.

Model
-----
Integrity follows Biba: lower integrity "infects" higher integrity on
combination, so `join` takes the *minimum* integrity of its inputs.

Confidentiality follows Bell-LaPadula: combining public data with secret data
produces something that must be handled as secret, so `join` takes the
*maximum* confidentiality of its inputs.

A session (or a value) therefore carries a single `Label`, and merging two
provenance paths is `Label.join`, which can only move integrity down and
confidentiality up -- i.e. it can only ever make the result *more*
restrictive. This is exactly the "most restrictive combination of everything
read so far" ceiling described in the architecture.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from functools import reduce


class Integrity(IntEnum):
    """Biba integrity levels. Higher is more trustworthy."""

    UNTRUSTED = 0
    TENTATIVE = 1
    TRUSTED = 2


class Confidentiality(IntEnum):
    """Bell-LaPadula confidentiality levels. Higher is more secret."""

    PUBLIC = 0
    INTERNAL = 1
    PRIVATE = 2
    SECRET = 3


@dataclass(frozen=True, slots=True)
class Label:
    """An immutable point in the integrity x confidentiality lattice."""

    integrity: Integrity = Integrity.TRUSTED
    confidentiality: Confidentiality = Confidentiality.PUBLIC

    # ---- lattice operations ------------------------------------------------

    def join(self, other: Label) -> Label:
        """Least upper bound in the *restrictiveness* order.

        Combining two labels can only lower integrity and raise
        confidentiality -- it can never make the result less restrictive than
        either input. This is the operation used whenever two values are
        combined (e.g. an email body built from a trusted template and an
        untrusted attachment).
        """
        return Label(
            integrity=min(self.integrity, other.integrity),
            confidentiality=max(self.confidentiality, other.confidentiality),
        )

    def meet(self, other: Label) -> Label:
        """Greatest lower bound. Included for lattice completeness; the
        enforcement path only ever uses `join`.
        """
        return Label(
            integrity=max(self.integrity, other.integrity),
            confidentiality=min(self.confidentiality, other.confidentiality),
        )

    # ---- partial order ------------------------------------------------------

    def is_at_least_as_restrictive_as(self, other: Label) -> bool:
        """True if `self` is >= `other` in the restrictiveness partial order.

        "At least as restrictive" means integrity is no higher and
        confidentiality is no lower than `other`. The bottom of this order
        (least restrictive) is TRUSTED/PUBLIC; the top (most restrictive) is
        UNTRUSTED/SECRET.
        """
        return self.integrity <= other.integrity and self.confidentiality >= other.confidentiality

    def satisfies_ceiling(self, ceiling: Label) -> bool:
        """True if a tool call declaring a maximum tolerable restrictiveness
        of `ceiling` may proceed, given the session currently holds `self` as
        its accumulated label.

        A call is permitted only if the session's accumulated integrity is at
        least as high, and its confidentiality at most as high, as the tool's
        declared ceiling.
        """
        integrity_ok = self.integrity >= ceiling.integrity
        confidentiality_ok = self.confidentiality <= ceiling.confidentiality
        return integrity_ok and confidentiality_ok

    # ---- constructors --------------------------------------------------

    @staticmethod
    def bottom() -> Label:
        """Least restrictive label: fully trusted, fully public. Identity
        element for `join`.
        """
        return Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PUBLIC)

    @staticmethod
    def top() -> Label:
        """Most restrictive label: fully untrusted, fully secret."""
        return Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.SECRET)

    @staticmethod
    def untrusted() -> Label:
        """Shorthand for content from an unauthenticated external source."""
        return Label(integrity=Integrity.UNTRUSTED, confidentiality=Confidentiality.PUBLIC)

    @staticmethod
    def private() -> Label:
        """Shorthand for trusted-but-sensitive data, e.g. the user's own inbox."""
        return Label(integrity=Integrity.TRUSTED, confidentiality=Confidentiality.PRIVATE)


def join_all(labels: Iterable[Label]) -> Label:
    """Fold `Label.join` over an iterable, starting from the least restrictive
    identity element. Used to compute a session's current label ceiling from
    every value it has touched so far.
    """
    return reduce(Label.join, labels, Label.bottom())
