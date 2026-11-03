from __future__ import annotations

import asyncio

from agentshield_eval.local_benchmark import run_local_benchmark


def test_local_benchmark_reports_full_and_ablation_measurements() -> None:
    results = asyncio.run(run_local_benchmark(samples=1))
    by_config = {result.config: result for result in results}

    assert set(by_config) == {
        "full",
        "no_cedar_policy",
        "no_label_lattice",
        "no_trifecta",
        "unresponsive_approval_reviewer",
    }
    assert by_config["full"].benign_utility == 1.0
    assert by_config["full"].targeted_asr == 0.0
    assert by_config["no_label_lattice"].targeted_asr == 0.5
    assert by_config["unresponsive_approval_reviewer"].benign_utility == 0.0
    assert all(result.median_latency_ms > 0 for result in results)
