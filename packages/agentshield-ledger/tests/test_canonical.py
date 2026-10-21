import pytest
from agentshield_ledger.verify.canonical import CanonicalizationError, canonicalize


def test_key_order_is_irrelevant() -> None:
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b


def test_output_is_compact_no_whitespace() -> None:
    out = canonicalize({"a": [1, 2, 3]})
    assert out == b'{"a":[1,2,3]}'


def test_floats_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": 1.5})


def test_nested_floats_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": [1, {"b": 2.0}]})


def test_bools_are_not_mistaken_for_floats() -> None:
    # bool is a subclass of int in Python; must not be rejected as a float.
    out = canonicalize({"flag": True})
    assert out == b'{"flag":true}'


def test_same_structure_different_instances_match() -> None:
    assert canonicalize([1, "x", {"k": None}]) == canonicalize([1, "x", {"k": None}])


def test_unicode_is_preserved_not_escaped() -> None:
    out = canonicalize({"name": "café"})
    assert "café".encode() in out
