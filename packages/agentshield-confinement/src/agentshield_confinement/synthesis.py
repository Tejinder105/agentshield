"""The first of the two narrowly-scoped, non-authoritative LLM roles the
plan allows (see the architecture doc's "An LLM is permitted in exactly
two ... roles" paragraph, and `agentshield_sdk.quarantine` for the second
role, schema-constrained parsing): synthesizing a *candidate* initial
Cedar policy from the user's task description, at session start.

This module's output is never trusted directly. `synthesize_initial_policy`
always re-validates the LLM's candidate text against the real Cedar
schema before using it (`PolicyStore` does this on construction, via
`cedarpy.validate_policies`), and fails closed to a deny-all policy if the
candidate is unusable for any reason -- a hallucinated or malformed policy
document degrades the system to "nothing is permitted yet", never to
"something unintended is permitted".

Subsequent updates to this policy, after the session has started, are a
separate concern handled by `agentshield_confinement.gate`, not this
module: the initial synthesis establishes a starting point with no prior
policy to narrow from, so monotonic confinement's subsumption check does
not apply to it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.policies import PolicyStore, PolicyValidationError

#: What the session starts with if synthesis fails or produces something
#: unusable. An empty Cedar policy set (no `permit` statements at all)
#: authorizes nothing -- Cedar, like this project's PDP, is default-deny.
DEFAULT_DENY_ALL_POLICY = "// no policy synthesized yet: default-deny\n"


class PolicySynthesizer(Protocol):
    """A tool-less LLM client that proposes Cedar policy text from a task
    description. Implementations talk to whatever model/provider they
    like; this module only ever sees plain text in, plain text out, and
    never grants the synthesizer any tool-calling ability of its own.
    """

    async def synthesize(
        self, *, user_task: str, schema_text: str, tools: list[dict[str, Any]]
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class SynthesisResult:
    """The outcome of one initial-policy synthesis attempt.

    `policy_store` is always a *valid*, ready-to-use `PolicyStore` --
    either the synthesizer's own validated candidate (`accepted=True`), or
    the deny-all fallback (`accepted=False`). A caller never has to handle
    "synthesis failed" as a distinct branch; it only has to decide whether
    `accepted=False` warrants surfacing a warning to the user who expected
    their task to grant some tool access.
    """

    policy_store: PolicyStore
    accepted: bool
    raw_candidate: str
    detail: str


async def synthesize_initial_policy(
    synthesizer: PolicySynthesizer,
    *,
    user_task: str,
    schema: GeneratedSchema,
    tools: list[dict[str, Any]],
) -> SynthesisResult:
    """Ask `synthesizer` for a candidate policy, then validate it for
    real. Never raises: an LLM failure and a malformed candidate both
    degrade to a deny-all `PolicyStore`, never to an exception a caller
    might mishandle into "allow everything".
    """
    try:
        candidate = await synthesizer.synthesize(
            user_task=user_task, schema_text=schema.schema_text, tools=tools
        )
    except Exception as exc:
        return SynthesisResult(
            policy_store=PolicyStore(policy_text=DEFAULT_DENY_ALL_POLICY, schema=schema),
            accepted=False,
            raw_candidate="",
            detail=f"policy synthesizer raised, falling back to deny-all: {exc}",
        )

    try:
        store = PolicyStore(policy_text=candidate, schema=schema)
    except PolicyValidationError as exc:
        return SynthesisResult(
            policy_store=PolicyStore(policy_text=DEFAULT_DENY_ALL_POLICY, schema=schema),
            accepted=False,
            raw_candidate=candidate,
            detail=f"synthesized policy failed Cedar validation, falling back to deny-all: {exc}",
        )

    return SynthesisResult(
        policy_store=store,
        accepted=True,
        raw_candidate=candidate,
        detail="synthesized policy validated and accepted as the session's initial policy",
    )
