from __future__ import annotations

from typing import Any

from agentshield_ledger.verify.hashchain import GENESIS_HASH, ChainedEntry, verify_chain
from hypothesis import given
from hypothesis import strategies as st

_entry = st.dictionaries(
    st.text(min_size=1, max_size=10),
    st.one_of(st.text(max_size=20), st.integers(), st.booleans()),
    max_size=5,
)


def test_first_entry_chains_from_genesis() -> None:
    chained = ChainedEntry.first({"a": 1})
    assert chained.seq == 0
    assert chained.prev_hash == GENESIS_HASH
    assert verify_chain([chained])


def test_chain_extends_correctly() -> None:
    e0 = ChainedEntry.first({"a": 1})
    e1 = e0.extend({"a": 2})
    e2 = e1.extend({"a": 3})
    assert e1.prev_hash == e0.entry_hash
    assert e2.prev_hash == e1.entry_hash
    assert verify_chain([e0, e1, e2])


def test_empty_chain_is_valid() -> None:
    assert verify_chain([])


def test_tampering_with_an_entry_breaks_the_chain() -> None:
    e0 = ChainedEntry.first({"a": 1})
    e1 = e0.extend({"a": 2})
    tampered_e1 = ChainedEntry(
        seq=e1.seq, entry={"a": 999}, prev_hash=e1.prev_hash, entry_hash=e1.entry_hash
    )
    assert not verify_chain([e0, tampered_e1])


def test_reordering_entries_breaks_the_chain() -> None:
    e0 = ChainedEntry.first({"a": 1})
    e1 = e0.extend({"a": 2})
    e2 = e1.extend({"a": 3})
    assert not verify_chain([e0, e2, e1])


def test_dropping_an_entry_breaks_the_chain() -> None:
    e0 = ChainedEntry.first({"a": 1})
    e1 = e0.extend({"a": 2})
    e2 = e1.extend({"a": 3})
    assert not verify_chain([e0, e2])


@given(entries=st.lists(_entry, min_size=1, max_size=15))
def test_any_sequence_of_entries_builds_a_verifiable_chain(
    entries: list[dict[str, Any]],
) -> None:
    chain: list[ChainedEntry] = []
    for e in entries:
        chain.append(chain[-1].extend(e) if chain else ChainedEntry.first(e))
    assert verify_chain(chain)
