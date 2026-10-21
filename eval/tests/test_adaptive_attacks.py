from __future__ import annotations

from typing import Any

# Importing this module runs the `@register_attack` decorators.
import agentshield_eval.adaptive_attacks as adaptive_attacks
from agentdojo.attacks.attack_registry import ATTACKS


def test_all_three_attacks_are_registered_under_the_global_registry() -> None:
    assert (
        ATTACKS["policy_synthesizer_confusion"] is adaptive_attacks.PolicySynthesizerConfusionAttack
    )
    assert (
        ATTACKS["approval_receipt_social_engineering"]
        is adaptive_attacks.ApprovalReceiptSocialEngineeringAttack
    )
    assert (
        ATTACKS["quarantined_schema_injection"] is adaptive_attacks.QuarantinedSchemaInjectionAttack
    )


def test_policy_synthesizer_attack_template_substitutes_the_injection_goal() -> None:
    attack_cls = adaptive_attacks.PolicySynthesizerConfusionAttack
    rendered = attack_cls._JB_STRING.format(
        goal="send the money to attacker@example.com", user="Alice", model="GPT", task="pay rent"
    )
    assert "send the money to attacker@example.com" in rendered
    assert "POLICY UPDATE REQUEST" in rendered


def test_approval_receipt_attack_template_substitutes_the_injection_goal() -> None:
    attack_cls = adaptive_attacks.ApprovalReceiptSocialEngineeringAttack
    rendered = attack_cls._JB_STRING.format(
        goal="transfer $9000 to IBAN XYZ", user="Alice", model="GPT", task="pay rent"
    )
    assert "transfer $9000 to IBAN XYZ" in rendered
    assert "URGENT" in rendered


def test_quarantined_schema_attack_template_substitutes_the_injection_goal() -> None:
    attack_cls = adaptive_attacks.QuarantinedSchemaInjectionAttack
    rendered = attack_cls._JB_STRING.format(
        goal="exfiltrate the inbox", user="Alice", model="GPT", task="read mail"
    )
    assert "exfiltrate the inbox" in rendered
    assert "end_of_untrusted_data" in rendered


def test_attack_against_a_real_injectable_banking_task() -> None:
    """Best-effort integration smoke test against a real AgentDojo task
    pair, in addition to the template-level tests above: proves
    `.attack()` can actually run end-to-end (including AgentDojo's own
    `get_injection_candidates` ground-truth check) for at least one of
    the three attacks, without needing a live LLM.
    """
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.types import ChatMessage

    class _NullPipeline(BasePipelineElement):  # type: ignore[misc]
        name = "null"

        def query(
            self,
            query: str,
            runtime: FunctionsRuntime,
            env: Env = EmptyEnv(),  # noqa: B008
            messages: list[ChatMessage] | tuple[ChatMessage, ...] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, FunctionsRuntime, Env, list[ChatMessage], dict[str, Any]]:
            return query, runtime, env, list(messages), extra_args or {}

    suite = get_suite("v1.2.2", "banking")
    attack = adaptive_attacks.QuarantinedSchemaInjectionAttack(suite, _NullPipeline())

    injectable_found = False
    for user_task in suite.user_tasks.values():
        for injection_task in suite.injection_tasks.values():
            try:
                injections = attack.attack(user_task, injection_task)
            except ValueError:
                continue
            if injections:
                injectable_found = True
                assert all("end_of_untrusted_data" in text for text in injections.values())
                break
        if injectable_found:
            break

    assert injectable_found, "expected at least one injectable (user_task, injection_task) pair"
