"""`python -m agentshield_eval`: run the real AgentDojo benchmark against
a live LLM provider, with Agent Shield's `DecisionPipeline` enforcing
every call.

This is the one module in this package that actually talks to a real
model provider and therefore needs credentials (`OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, ...) and network access --
it is deliberately never imported by this package's own test suite, which
exercises every other module's logic against fakes and fixtures instead.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from agentdojo.agent_pipeline.agent_pipeline import get_llm
from agentdojo.agent_pipeline.llms.google_llm import GoogleLLM
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.models import MODEL_PROVIDERS, ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from agentshield_eval.harness import build_agent_shield_pipeline
from agentshield_eval.metrics import compute_metrics
from agentshield_eval.tool_profiles import SUITE_PROFILES

DEFAULT_POLICY_TEXT = "permit(principal, action, resource);"

#: Default OpenRouter model when ``--model`` is not set explicitly for
#: the ``openrouter`` provider.  ``openrouter/auto`` is OpenRouter's
#: meta-router that picks a model matching the request's requirements
#: (tool calling, context length, etc.).
DEFAULT_OPENROUTER_MODEL = "openrouter/auto"


def _build_openrouter_llm(model: str) -> OpenAILLM:
    """Creates an AgentDojo-compatible ``OpenAILLM`` backed by OpenRouter.

    OpenRouter exposes an OpenAI-compatible ``/v1/chat/completions``
    endpoint, so we just point the ``openai.OpenAI`` client at it with the
    user's ``OPENROUTER_API_KEY``.
    """
    import openai

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is required for OpenRouter runs.  "
            "Set it in your .env or shell environment."
        )
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    return OpenAILLM(client, model)


def _build_groq_llm(model: str) -> OpenAILLM:
    """Creates an AgentDojo-compatible ``OpenAILLM`` backed by Groq.

    Groq exposes an ultra-fast OpenAI-compatible ``/v1/chat/completions``
    endpoint with native tool calling support.
    """
    import openai

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is required for Groq runs.  "
            "Set it in your .env or shell environment."
        )
    base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    return OpenAILLM(client, model)


def _resolve_provider_and_model(
    raw_model: str,
) -> tuple[str, str]:
    """Determines (provider, model) from the ``--model`` flag.

    Resolution order:
    1. If *raw_model* starts with ``groq/`` or is a known Groq model, use Groq.
    2. If *raw_model* is ``"openrouter"`` or starts with ``openrouter/``
       or ends with ``:free``, it is an OpenRouter model.
    3. If it starts with ``gemini-``, it is a Google model.
    4. If it matches one of AgentDojo's builtin ``ModelsEnum`` values,
       the provider comes from ``MODEL_PROVIDERS``.
    5. Fallback: if GROQ_API_KEY is set and OPENROUTER_API_KEY is not, route to Groq.
    6. Fallback: if OPENROUTER_API_KEY is set, route to OpenRouter.
    """
    # Explicit Groq identifiers
    if raw_model.startswith("groq/"):
        return "groq", raw_model.removeprefix("groq/")
    if raw_model in ("openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b", "llama-3.3-70b-versatile"):
        return "groq", raw_model

    # Explicit OpenRouter identifiers
    if raw_model == "openrouter" or raw_model.startswith("openrouter/") or ":free" in raw_model:
        model = raw_model if raw_model != "openrouter" else DEFAULT_OPENROUTER_MODEL
        return "openrouter", model

    # Google / Gemini
    if raw_model.startswith("gemini-"):
        return "google", raw_model

    # AgentDojo builtin model enum
    try:
        enum_model = ModelsEnum(raw_model)
        return MODEL_PROVIDERS[enum_model], raw_model
    except ValueError:
        pass

    # Provider fallbacks based on environment keys
    if os.getenv("GROQ_API_KEY") and not os.getenv("OPENROUTER_API_KEY"):
        return "groq", raw_model
    if os.getenv("OPENROUTER_API_KEY"):
        return "openrouter", raw_model
    if os.getenv("GROQ_API_KEY"):
        return "groq", raw_model

    raise ValueError(
        f"Unsupported model '{raw_model}'.  Use an AgentDojo model identifier, "
        "a Gemini model name, or set GROQ_API_KEY / OPENROUTER_API_KEY."
    )


def _run_suite(args: argparse.Namespace) -> int:
    suite = get_suite(args.benchmark_version, args.suite)
    provider, model = _resolve_provider_and_model(args.model)

    if provider == "groq":
        llm = _build_groq_llm(model)
    elif provider == "openrouter":
        llm = _build_openrouter_llm(model)
    elif provider == "google":
        from google import genai

        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GOOGLE_API_KEY is required for Google Gemini live runs")
        llm = GoogleLLM(model, genai.Client(api_key=api_key))
    else:
        llm = get_llm(provider, model, None, "tool")

    policy_text = (
        Path(args.policy_file).read_text(encoding="utf-8")
        if args.policy_file is not None
        else DEFAULT_POLICY_TEXT
    )

    benchmark_pipeline = build_agent_shield_pipeline(
        llm, suite, session_id=f"eval-{suite.name}", policy_text=policy_text
    )

    logdir = Path(args.logdir) if args.logdir is not None else None
    with OutputLogger(logdir=str(logdir) if logdir is not None else None):
        benign = benchmark_suite_without_injections(
            benchmark_pipeline.pipeline, suite, logdir, args.force_rerun
        )

        if args.attack is None:
            print(
                json.dumps(
                    {"suite": suite.name, "benign_utility": benign["utility_results"]}, indent=2
                )
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


def _run_local(args: argparse.Namespace) -> int:
    import asyncio

    from agentshield_eval.local_benchmark import run_local_benchmark

    results = asyncio.run(run_local_benchmark(args.samples))
    print(json.dumps([result.as_dict() for result in results], indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentshield-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_suite = subparsers.add_parser(
        "run-suite", help="run one AgentDojo suite against a live model"
    )
    run_suite.add_argument("--suite", required=True, choices=sorted(SUITE_PROFILES))
    run_suite.add_argument(
        "--model",
        required=True,
        help=(
            "Model identifier. AgentDojo builtins (gpt-4o-2024-05-13, "
            "claude-3-5-sonnet-20241022, ...), Gemini names (gemini-2.0-flash-001), "
            "or any OpenRouter model slug (e.g. openrouter/auto, "
            "meta-llama/llama-3-70b-chat-hf:free, "
            "nvidia/nemotron-3-ultra-550b-a55b:free).  "
            "When OPENROUTER_API_KEY is set, unknown model names are automatically "
            "routed through OpenRouter."
        ),
    )
    run_suite.add_argument("--attack", default=None)
    run_suite.add_argument("--benchmark-version", default="v1.2.2")
    run_suite.add_argument("--policy-file", default=None)
    run_suite.add_argument("--logdir", default=None)
    run_suite.add_argument("--force-rerun", action="store_true")
    run_suite.set_defaults(handler=_run_suite)

    run_local = subparsers.add_parser(
        "run-local",
        help="measure deterministic gateway behavior without a live model provider",
    )
    run_local.add_argument("--samples", type=int, default=1000)
    run_local.set_defaults(handler=_run_local)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    result: int = handler(args)
    return result


if __name__ == "__main__":
    sys.exit(main())
