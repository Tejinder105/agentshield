from __future__ import annotations

from itertools import permutations

from agentshield_core.trifecta import TrifectaLeg, TrifectaState
from hypothesis import given
from hypothesis import strategies as st

legs = st.sampled_from(list(TrifectaLeg))


def test_initial_state_has_no_legs() -> None:
    state = TrifectaState()
    assert state.acquired_legs() == frozenset()


def test_acquiring_two_legs_does_not_complete_trifecta() -> None:
    state = TrifectaState().with_leg_acquired(TrifectaLeg.UNTRUSTED_INPUT)
    state = state.with_leg_acquired(TrifectaLeg.PRIVATE_DATA)
    assert not state.would_complete_trifecta(TrifectaLeg.PRIVATE_DATA)  # already held
    assert state.would_complete_trifecta(TrifectaLeg.EXTERNAL_COMMUNICATION)


def test_completing_the_third_leg_is_detected() -> None:
    state = TrifectaState(untrusted_input=True, private_data=True)
    assert state.would_complete_trifecta(TrifectaLeg.EXTERNAL_COMMUNICATION)
    completed = state.with_leg_acquired(TrifectaLeg.EXTERNAL_COMMUNICATION)
    assert completed.acquired_legs() == frozenset(TrifectaLeg)


def test_reacquiring_an_already_held_leg_never_completes_the_trifecta() -> None:
    state = TrifectaState(untrusted_input=True)
    assert not state.would_complete_trifecta(TrifectaLeg.UNTRUSTED_INPUT)


@given(st.permutations(list(TrifectaLeg)))
def test_order_independence_of_acquiring_all_three_legs(order: list[TrifectaLeg]) -> None:
    """Regardless of the order in which a session acquires the three legs,
    the trifecta is complete after exactly the third acquisition and not
    before -- the invariant must not depend on acquisition order.
    """
    state = TrifectaState()
    for i, leg in enumerate(order):
        would_complete = state.would_complete_trifecta(leg)
        if i < 2:
            assert not would_complete
        else:
            assert would_complete
        state = state.with_leg_acquired(leg)
    assert state.acquired_legs() == frozenset(TrifectaLeg)


def test_all_six_orderings_agree() -> None:
    """Exhaustive check over all 3! orderings, as a concrete complement to
    the hypothesis-generated property test above.
    """
    for order in permutations(TrifectaLeg):
        state = TrifectaState()
        for leg in order:
            state = state.with_leg_acquired(leg)
        assert state.acquired_legs() == frozenset(TrifectaLeg)
