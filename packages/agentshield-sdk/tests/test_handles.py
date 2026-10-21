from __future__ import annotations

import pytest
from agentshield_core.labels import Label
from agentshield_core.provenance import TaintedValue
from agentshield_sdk.handles import UnknownHandleError, VarHandle, VarStore


def test_token_format() -> None:
    handle = VarHandle(handle_id="3")
    assert handle.token == "var_3"  # noqa: S105 -- a handle token, not a credential


def test_parse_token_round_trips() -> None:
    assert VarHandle.parse_token("var_3") == VarHandle(handle_id="3")
    assert VarHandle.parse_token("not-a-token") is None
    assert VarHandle.parse_token("var_abc") is None  # non-numeric id
    assert VarHandle.parse_token("prefix var_3 suffix") is None  # not a full match


def test_put_allocates_increasing_ids() -> None:
    store = VarStore()
    h1 = store.put(TaintedValue.from_source("a", "src1", Label.untrusted()))
    h2 = store.put(TaintedValue.from_source("b", "src2", Label.untrusted()))
    assert h1.handle_id != h2.handle_id
    assert len(store) == 2


def test_get_returns_the_stored_tainted_value() -> None:
    store = VarStore()
    tainted = TaintedValue.from_source("secret", "src", Label.private())
    handle = store.put(tainted)
    fetched = store.get(handle)
    assert fetched.value == "secret"
    assert fetched.label == Label.private()


def test_get_of_unknown_handle_raises() -> None:
    store = VarStore()
    with pytest.raises(UnknownHandleError):
        store.get(VarHandle(handle_id="999"))


def test_resolve_in_substitutes_exact_token_matches() -> None:
    store = VarStore()
    handle = store.put(TaintedValue.from_source({"amount": 42}, "src", Label.untrusted()))

    resolved = store.resolve_in({"payload": handle.token, "other": "unchanged"})

    assert resolved == {"payload": {"amount": 42}, "other": "unchanged"}


def test_resolve_in_recurses_through_lists_and_tuples() -> None:
    store = VarStore()
    handle = store.put(TaintedValue.from_source("value", "src", Label.untrusted()))

    resolved = store.resolve_in({"items": [handle.token, "plain", (handle.token,)]})

    assert resolved == {"items": ["value", "plain", ("value",)]}


def test_resolve_in_leaves_non_tokens_untouched() -> None:
    store = VarStore()
    assert store.resolve_in("just a string") == "just a string"
    assert store.resolve_in(42) == 42
    assert store.resolve_in(None) is None


def test_resolve_in_does_not_substitute_a_token_embedded_in_a_larger_string() -> None:
    store = VarStore()
    handle = store.put(TaintedValue.from_source("value", "src", Label.untrusted()))
    text = f"please see {handle.token} for details"
    assert store.resolve_in(text) == text  # unchanged: not an exact match


def test_resolve_in_raises_for_an_unknown_token_rather_than_passing_it_through() -> None:
    """A forged `var_999` must fail loudly, not silently become the
    literal string `"var_999"` as if that were an intentional value.
    """
    store = VarStore()
    with pytest.raises(UnknownHandleError):
        store.resolve_in({"arg": "var_999"})


def test_label_of_joins_labels_of_every_referenced_handle() -> None:
    store = VarStore()
    public_handle = store.put(TaintedValue.from_source("a", "src1", Label.bottom()))
    secret_handle = store.put(TaintedValue.from_source("b", "src2", Label.private()))

    label = store.label_of({"x": public_handle.token, "y": secret_handle.token})

    assert label == Label.private()  # join of PUBLIC/TRUSTED and PRIVATE/TRUSTED


def test_label_of_finds_tokens_embedded_in_a_larger_string() -> None:
    """Unlike `resolve_in`, `label_of` is substring-aware -- a planner
    merely *mentioning* a handle inside a longer string still counts as
    touching that value's taint.
    """
    store = VarStore()
    handle = store.put(TaintedValue.from_source("secret", "src", Label.private()))

    label = store.label_of(f"please see {handle.token} for details")

    assert label == Label.private()


def test_label_of_an_object_with_no_tokens_is_bottom() -> None:
    store = VarStore()
    assert store.label_of({"plain": "value", "n": 1}) == Label.bottom()


def test_label_of_ignores_a_token_shaped_string_that_was_never_issued() -> None:
    """Unlike `resolve_in`, `label_of` is a best-effort scan used only for
    computing an input label, so it silently skips an unrecognized token
    rather than raising -- `resolve_in`'s stricter behavior is what
    actually guards dispatch.
    """
    store = VarStore()
    assert store.label_of("var_999") == Label.bottom()
