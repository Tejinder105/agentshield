"""Monotonic confinement: the gate every policy update after session
start must pass through (advanced feature #1 in the plan, and "the
single strongest property the system can claim"). The session's
effective action space can only shrink without a human in the loop --
`propose_policy_update` auto-applies a candidate only when
`agentshield_policy.subsumption.check_subsumption` *proves* it narrows
the current policy; anything it cannot prove narrowing for -- a genuine
expansion, or a construct the subsumption checker cannot reason about --
leaves the current policy untouched and returns `Decision.require_approval`.

The session's *initial* policy (`agentshield_confinement.synthesis`) is
exempt from this gate by construction: there is no previous policy yet to
narrow from.
"""

from __future__ import annotations

from agentshield_core.decision import Decision, Obligation, ObligationKind
from agentshield_policy.mcp_schema import GeneratedSchema
from agentshield_policy.policies import PolicyStore, PolicyValidationError
from agentshield_policy.subsumption import SubsumptionReport, check_subsumption

STAGE = "monotonic_confinement"


def propose_policy_update(
    current: PolicyStore,
    candidate_policy_text: str,
    *,
    schema: GeneratedSchema,
    session_id: str,
) -> Decision:
    """Attempt to apply `candidate_policy_text` as `current`'s new policy.

    - A malformed candidate (fails Cedar's own parse/schema validation)
      never reaches the subsumption checker at all: `Decision.deny`, and
      `current` is left completely untouched.
    - A candidate *proven* to narrow the current policy is applied in
      place (`current.reload(...)`) and `Decision.allow` is returned.
    - Everything else -- a proven expansion, or anything the subsumption
      checker could not prove either way -- is left unapplied and
      `Decision.require_approval` is returned, carrying the full
      `SubsumptionReport` (as a plain dict, via the `ObligationKind.
      RECORD_SUBSUMPTION_EVIDENCE` obligation) for a human reviewer -- the
      console's policy editor, in particular -- to inspect.
    """
    try:
        PolicyStore(policy_text=candidate_policy_text, schema=schema)
    except PolicyValidationError as exc:
        return Decision.deny(f"candidate policy failed Cedar validation: {exc}", stage=STAGE)

    report = check_subsumption(
        old_policy_text=current.policy_text,
        new_policy_text=candidate_policy_text,
        schema=schema,
        session_id=session_id,
    )

    if report.is_narrowing:
        current.reload(candidate_policy_text)
        return Decision.allow(
            "candidate policy proven to narrow the session's current action space", stage=STAGE
        )

    return Decision.require_approval(
        _explain(report),
        stage=STAGE,
        obligations=(
            Obligation(
                kind=ObligationKind.RECORD_SUBSUMPTION_EVIDENCE,
                detail={"report": _report_to_dict(report)},
            ),
        ),
    )


def _explain(report: SubsumptionReport) -> str:
    violations = report.violations
    if not violations:
        return "candidate policy could not be proven to narrow the current policy; needs review"
    names = ", ".join(f"{v.action} ({v.outcome.value})" for v in violations)
    return f"candidate policy is not a proven narrowing for: {names}; requires human approval"


def _report_to_dict(report: SubsumptionReport) -> dict[str, object]:
    return {
        "outcome": report.outcome.value,
        "per_action": [
            {"action": r.action, "outcome": r.outcome.value, "detail": r.detail}
            for r in report.per_action
        ],
    }
