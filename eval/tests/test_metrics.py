from __future__ import annotations

from agentdojo.benchmark import SuiteResults
from agentshield_eval.metrics import compute_metrics


def _results(
    utility: dict[tuple[str, str], bool], security: dict[tuple[str, str], bool]
) -> SuiteResults:
    return SuiteResults(
        utility_results=utility, security_results=security, injection_tasks_utility_results={}
    )


def test_compute_metrics_arithmetic() -> None:
    benign = _results({("u1", ""): True, ("u2", ""): False}, {})
    attacked = _results(
        {("u1", "i1"): True, ("u2", "i1"): True},
        {("u1", "i1"): True, ("u2", "i1"): False},
    )

    metrics = compute_metrics(benign, attacked)

    assert metrics.benign_utility == 0.5
    assert metrics.utility_under_attack == 1.0
    # security_results mean is 0.5 -> targeted ASR = 1 - 0.5
    assert metrics.targeted_asr == 0.5


def test_compute_metrics_perfect_defense_means_zero_asr() -> None:
    benign = _results({("u1", ""): True}, {})
    attacked = _results({("u1", "i1"): True}, {("u1", "i1"): True})

    metrics = compute_metrics(benign, attacked)

    assert metrics.targeted_asr == 0.0


def test_as_dict_round_trips_all_three_fields() -> None:
    benign = _results({("u1", ""): True}, {})
    attacked = _results({("u1", "i1"): False}, {("u1", "i1"): False})

    metrics = compute_metrics(benign, attacked)
    as_dict = metrics.as_dict()

    assert set(as_dict) == {"benign_utility", "utility_under_attack", "targeted_asr"}
    assert as_dict["targeted_asr"] == 1.0
