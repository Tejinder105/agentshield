"""`python -m agentshield_eval`: run the real AgentDojo benchmark against
a live LLM provider, with Agent Shield's `DecisionPipeline` enforcing
every call.

This is the one module in this package that actually talks to a real
model provider and therefore needs credentials (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, ...) and network access -- it is deliberately never
imported by this package's own test suite, which exercises every other
module's logic against fakes and fixtures instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentdojo.agent_pipeline.agent_pipeline import get_llm
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.models import MODEL_PROVIDERS, ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from agentshield_eval.harness import build_agent_shield_pipeline
from agentshield_eval.metrics import compute_metrics
from agentshield_eval.tool_profiles import SUITE_PROFILES

DEFAULT_POLICY_TEXT = "permit(principal, action, resource);"


def _run_suite(args: argparse.Namespace) -> int:
    suite = get_suite(args.benchmark_version, args.suite)
    provider = MODEL_PROVIDERS[ModelsEnum(args.model)]
    llm = get_llm(provider, args.model, None, "tool")

    policy_text = (
        Path(args.policy_file).read_text(encoding="utf-8")
        if args.policy_file is not None
        else DEFAULT_POLICY_TEXT
    )

    benchmark_pipeline = build_agent_shield_pipeline(
        llm, suite, session_id=f"eval-{suite.name}", policy_text=policy_text
    )

    logdir = Path(args.logdir) if args.logdir is not None else None
    benign = benchmark_suite_without_injections(
        benchmark_pipeline.pipeline, suite, logdir, args.force_rerun
    )

    if args.attack is None:
        print(
            json.dumps({"suite": suite.name, "benign_utility": benign["utility_results"]}, indent=2)
        )
        return 0

    from agentdojo.attacks.attack_registry import load_attack

    attack = load_attack(args.attack, suite, benchmark_pipeline.pipeline)
    attacked = benchmark_suite_with_injections(
        benchmark_pipeline.pipeline, suite, attack, logdir, args.force_rerun
    )

    metrics = compute_metrics(benign, attacked)
    print(json.dumps({"suite": suite.name, "attack": args.attack, **metrics.as_dict()}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_suite = subparsers.add_parser(
        "run-suite", help="run one AgentDojo suite against a live model"
    )
    run_suite.add_argument("--suite", required=True, choices=sorted(SUITE_PROFILES))
    run_suite.add_argument("--model", required=True)
    run_suite.add_argument("--attack", default=None)
    run_suite.add_argument("--benchmark-version", default="v1.2.2")
    run_suite.add_argument("--policy-file", default=None)
    run_suite.add_argument("--logdir", default=None)
    run_suite.add_argument("--force-rerun", action="store_true")
    run_suite.set_defaults(handler=_run_suite)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    result: int = handler(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
