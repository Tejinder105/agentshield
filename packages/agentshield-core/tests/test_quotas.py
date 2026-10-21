from __future__ import annotations

from agentshield_core.quotas import Quota, QuotaStore


def test_unregistered_capability_is_unlimited() -> None:
    store = QuotaStore()
    assert store.check("unknown", {"amount": 99}) is None
    store.consume("unknown", {"amount": 99})
    assert store.check("unknown", {"amount": 1}) is None


def test_call_quota_denies_the_call_that_would_exceed_it() -> None:
    store = QuotaStore()
    store.register("c1", Quota(max_calls=2))
    assert store.check("c1", {}) is None
    store.consume("c1", {})
    assert store.check("c1", {}) is None
    store.consume("c1", {})
    reason = store.check("c1", {})
    assert reason is not None
    assert "call quota" in reason


def test_spend_quota_uses_integer_minor_units_only() -> None:
    store = QuotaStore()
    store.register("c1", Quota(max_spend=100, spend_arg="amount_usd"))
    assert store.check("c1", {"amount_usd": 40}) is None
    store.consume("c1", {"amount_usd": 40})
    assert store.check("c1", {"amount_usd": 60}) is None
    store.consume("c1", {"amount_usd": 60})
    assert store.check("c1", {"amount_usd": 1}) is not None


def test_non_integer_spend_argument_is_treated_as_zero() -> None:
    store = QuotaStore()
    store.register("c1", Quota(max_spend=1, spend_arg="amount"))
    assert store.check("c1", {"amount": 10.5}) is None
    store.consume("c1", {"amount": 10.5})
    assert store.spend_used["c1"] == 0


def test_a_denied_check_does_not_consume() -> None:
    store = QuotaStore()
    store.register("c1", Quota(max_calls=1))
    store.consume("c1", {})
    assert store.check("c1", {}) is not None
    assert store.calls_used["c1"] == 1
