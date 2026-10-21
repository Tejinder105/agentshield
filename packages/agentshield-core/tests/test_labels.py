"""Property tests proving `Label.join` is a genuine lattice join.

If any of these fail, the information-flow argument for the rest of the
system (the label ceiling, the trifecta, the dual-LLM quarantine) is
unsound, not merely buggy -- these are the load-bearing proofs.
"""

from __future__ import annotations

from agentshield_core.labels import Confidentiality, Integrity, Label, join_all
from hypothesis import given
from hypothesis import strategies as st

integrities = st.sampled_from(list(Integrity))
confidentialities = st.sampled_from(list(Confidentiality))
labels = st.builds(Label, integrity=integrities, confidentiality=confidentialities)


@given(labels)
def test_join_idempotent(a: Label) -> None:
    assert a.join(a) == a


@given(labels, labels)
def test_join_commutative(a: Label, b: Label) -> None:
    assert a.join(b) == b.join(a)


@given(labels, labels, labels)
def test_join_associative(a: Label, b: Label, c: Label) -> None:
    assert a.join(b).join(c) == a.join(b.join(c))


@given(labels, labels)
def test_join_is_upper_bound(a: Label, b: Label) -> None:
    """The join must be at least as restrictive as each input: this is what
    makes it a valid *upper bound* in the restrictiveness order.
    """
    joined = a.join(b)
    assert joined.is_at_least_as_restrictive_as(a)
    assert joined.is_at_least_as_restrictive_as(b)


@given(labels, labels, labels)
def test_join_monotonic(a: Label, b: Label, c: Label) -> None:
    """Monotonicity: if a is at least as restrictive as b, then joining both
    with c preserves that ordering. This is what guarantees that adding more
    untrusted/secret inputs to a session can only ever hold the ceiling the
    same or raise it, never lower it.
    """
    if a.is_at_least_as_restrictive_as(b):
        assert a.join(c).is_at_least_as_restrictive_as(b.join(c))


@given(labels)
def test_bottom_is_identity_for_join(a: Label) -> None:
    assert a.join(Label.bottom()) == a
    assert Label.bottom().join(a) == a


@given(labels)
def test_top_absorbs_join(a: Label) -> None:
    assert a.join(Label.top()) == Label.top()


@given(st.lists(labels, min_size=0, max_size=10))
def test_join_all_is_at_least_as_restrictive_as_each_input(values: list[Label]) -> None:
    ceiling = join_all(values)
    for v in values:
        assert ceiling.is_at_least_as_restrictive_as(v)


@given(st.lists(labels, min_size=1, max_size=10))
def test_join_all_order_independent(values: list[Label]) -> None:
    """Because join is commutative and associative, the ceiling computed from
    a session's touched values must not depend on the order they were
    touched in.
    """
    forward = join_all(values)
    backward = join_all(list(reversed(values)))
    assert forward == backward


def test_satisfies_ceiling_basic_cases() -> None:
    trusted_public = Label(Integrity.TRUSTED, Confidentiality.PUBLIC)
    untrusted_secret = Label(Integrity.UNTRUSTED, Confidentiality.SECRET)

    # A fully trusted/public session satisfies even the strictest ceiling.
    assert trusted_public.satisfies_ceiling(untrusted_secret)
    # A fully untrusted/secret session only satisfies the loosest ceiling.
    assert not untrusted_secret.satisfies_ceiling(trusted_public)
    assert untrusted_secret.satisfies_ceiling(untrusted_secret)


def test_join_matches_biba_and_bell_lapadula_semantics() -> None:
    trusted = Label(Integrity.TRUSTED, Confidentiality.PUBLIC)
    untrusted = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
    secret = Label(Integrity.TRUSTED, Confidentiality.SECRET)

    # Untrusted content "infects" trusted content: integrity drops to the minimum.
    assert trusted.join(untrusted).integrity == Integrity.UNTRUSTED
    # Secret content "infects" public content: confidentiality rises to the maximum.
    assert trusted.join(secret).confidentiality == Confidentiality.SECRET
