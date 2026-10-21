from __future__ import annotations

import time

from agentshield_core.capabilities import Capability, arg_at_most, arg_equals, arg_in
from hypothesis import given
from hypothesis import strategies as st


def test_mint_creates_root_capability_with_no_parent() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=60)
    assert cap.parent_id is None
    assert cap.epoch == 1
    assert cap.caveat_count() == 0
    assert not cap.is_expired()


def test_attenuate_never_decreases_caveat_count() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=60)
    attenuated = cap.attenuate(arg_equals("to", "alice@example.com"))
    assert attenuated.caveat_count() == 1
    assert attenuated.caveat_count() >= cap.caveat_count()
    assert attenuated.parent_id == cap.capability_id


def test_attenuate_never_extends_expiry_beyond_parent() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=10)
    # Ask for a much longer TTL -- attenuation must clamp to the parent's expiry.
    attenuated = cap.attenuate(ttl_seconds=10_000)
    assert attenuated.expires_at <= cap.expires_at


def test_attenuate_can_shorten_expiry() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=10_000)
    attenuated = cap.attenuate(ttl_seconds=1)
    assert attenuated.expires_at < cap.expires_at


def test_derive_for_subagent_is_bound_to_new_session_but_still_an_attenuation() -> None:
    parent = Capability.mint("parent-session", "send_email", epoch=1, ttl_seconds=60)
    child = parent.derive_for_subagent("child-session", arg_equals("to", "alice@example.com"))
    assert child.session_id == "child-session"
    assert child.parent_id == parent.capability_id
    assert child.caveat_count() >= parent.caveat_count()


def test_expired_capability_never_permits() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=0.001)
    time.sleep(0.01)
    assert cap.is_expired()
    assert not cap.permits({"to": "alice@example.com"})


def test_stale_epoch_never_permits() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=60)
    assert cap.permits({}, current_epoch=1)
    assert not cap.permits({}, current_epoch=2)


def test_caveats_restrict_permitted_arguments() -> None:
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=60).attenuate(
        arg_in("to", ("alice@example.com", "bob@example.com"))
    )
    assert cap.permits({"to": "alice@example.com"})
    assert not cap.permits({"to": "mallory@example.com"})


def test_arg_at_most_caveat() -> None:
    cap = Capability.mint("session-1", "transfer_funds", epoch=1, ttl_seconds=60).attenuate(
        arg_at_most("amount_usd", 100)
    )
    assert cap.permits({"amount_usd": 50})
    assert not cap.permits({"amount_usd": 500})


# ---- the central property: attenuation can only shrink the permitted set --------------------

simple_args = st.fixed_dictionaries(
    {
        "to": st.sampled_from(["alice@example.com", "bob@example.com", "mallory@example.com"]),
        "amount_usd": st.integers(min_value=0, max_value=1000),
    }
)


@given(simple_args)
def test_attenuation_never_widens_the_permitted_set(args: dict[str, object]) -> None:
    """If an attenuated capability permits a call, the original (less
    constrained) capability must also permit it -- attenuation can only
    shrink what is allowed, never grow it. This is the monotonic-confinement
    property for a single capability's lifetime.
    """
    base = Capability.mint("session-1", "send_money", epoch=1, ttl_seconds=3600)
    attenuated = base.attenuate(
        arg_in("to", ("alice@example.com", "bob@example.com")),
        arg_at_most("amount_usd", 200),
    )
    if attenuated.permits(args, current_epoch=1):
        assert base.permits(args, current_epoch=1)


@given(st.lists(st.sampled_from(["alice@example.com", "bob@example.com"]), min_size=0, max_size=5))
def test_chained_attenuation_is_still_monotonically_narrowing(
    allowed_recipients: list[str],
) -> None:
    """Attenuating a capability multiple times in a row (as would happen
    across several sub-agent delegations) must still only narrow the
    permitted set at every step, not just the first.
    """
    cap = Capability.mint("session-1", "send_email", epoch=1, ttl_seconds=3600)
    history = [cap]
    for recipient in allowed_recipients:
        cap = cap.attenuate(arg_equals("to", recipient))
        history.append(cap)

    for earlier, later in zip(history, history[1:], strict=False):
        assert later.caveat_count() >= earlier.caveat_count()
