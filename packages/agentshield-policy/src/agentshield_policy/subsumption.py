"""Formal subsumption checking between two Cedar policy sets -- the
decision procedure behind monotonic confinement (advanced feature #1 in
the plan): a candidate policy update auto-applies only when it can be
*proven* to authorize no more than the current policy already does.

Two tiers, exactly as the plan calls for ("Cedar analysis with z3-solver
fallback"):

1. Cedar's own JSON policy representation (`cedarpy.policies_to_json_str`)
   is parsed into this module's small expression translator, which already
   handles the common, context-independent case for free: a policy with no
   `when`/`unless` conditions reduces to a trivial constant-true/false z3
   formula that the solver proves or refutes instantly, with no semantic
   guesswork involved -- Cedar's own structural representation of the
   policy *is* the analysis.
2. For policies whose conditions reference the tool's argument context
   (`context.input.*`), those conditions are translated into z3 formulas
   over typed symbolic variables (one per declared, required, primitively
   typed context attribute) and z3 is asked to *prove* that every context
   assignment the new policy would permit, the old policy already
   permitted too.

Translation deliberately supports a conservative, well-defined subset of
Cedar's expression language: literals, comparisons, boolean connectives,
literal-set membership, and `like` wildcard patterns over `String`,
`Long`, and `Bool`-typed context attributes. Anything outside that subset
-- an optional context attribute, a nested record or set-typed attribute,
an extension type like `ip()`/`decimal()`, an entity-hierarchy `in`
check, a policy template, and so on -- makes the whole action's result
`UNPROVEN` rather than guessing. This module is itself fail-closed,
exactly like `agentshield_policy.pdp`: an `UNPROVEN` result is treated
identically to a proven `EXPANSION` by `agentshield_policy.confinement` --
it blocks auto-apply and routes to a human -- never the other way around.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import cedarpy
import z3

from agentshield_policy.mcp_schema import GeneratedSchema

DEFAULT_TIMEOUT_MS = 2_000

# The only context-attribute Cedar types this module knows how to turn
# into a z3 sort. Anything else (an entity reference, a nested record, a
# set) is simply absent from `_context_var_types`'s result, which is what
# makes referencing it in a condition raise `UnsupportedConditionError`.
_SUPPORTED_ATTR_TYPES = {"String", "Long", "Bool"}


class SubsumptionOutcome(StrEnum):
    NARROWING = "NARROWING"
    EXPANSION = "EXPANSION"
    UNPROVEN = "UNPROVEN"


class UnsupportedConditionError(Exception):
    """Raised internally when a policy construct falls outside the
    translatable subset described in the module docstring. Always caught
    inside this module; never escapes `check_subsumption`.
    """


@dataclass(frozen=True, slots=True)
class ActionSubsumptionResult:
    action: str
    outcome: SubsumptionOutcome
    detail: str


@dataclass(frozen=True, slots=True)
class SubsumptionReport:
    outcome: SubsumptionOutcome
    per_action: tuple[ActionSubsumptionResult, ...]

    @property
    def is_narrowing(self) -> bool:
        return self.outcome is SubsumptionOutcome.NARROWING

    @property
    def requires_human_approval(self) -> bool:
        return not self.is_narrowing

    @property
    def violations(self) -> tuple[ActionSubsumptionResult, ...]:
        return tuple(r for r in self.per_action if r.outcome is not SubsumptionOutcome.NARROWING)


def check_subsumption(
    *,
    old_policy_text: str,
    new_policy_text: str,
    schema: GeneratedSchema,
    session_id: str,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> SubsumptionReport:
    """Prove (or fail to prove) that `new_policy_text` permits no more
    than `old_policy_text` does, for every action known to `schema`.

    Never raises: a parse failure on either policy text, or any
    unsupported construct, resolves to `UNPROVEN` for the affected
    action(s) rather than propagating an exception -- a caller (see
    `agentshield_policy.confinement.propose_policy_update`) that treats
    `UNPROVEN` the same as `EXPANSION` is already fail-closed by
    construction, with no need to additionally handle a raised error.
    """
    try:
        old_policies = json.loads(cedarpy.policies_to_json_str(old_policy_text))
        new_policies = json.loads(cedarpy.policies_to_json_str(new_policy_text))
    except Exception as exc:
        result = ActionSubsumptionResult(
            action="<policy set>",
            outcome=SubsumptionOutcome.UNPROVEN,
            detail=f"could not parse one of the two policy sets into Cedar's JSON form: {exc}",
        )
        return SubsumptionReport(outcome=SubsumptionOutcome.UNPROVEN, per_action=(result,))

    actions = sorted(_actions_in_schema(schema))
    results = [
        _check_one_action(
            action=action,
            old_policies=old_policies,
            new_policies=new_policies,
            schema=schema,
            session_id=session_id,
            timeout_ms=timeout_ms,
        )
        for action in actions
    ]
    return SubsumptionReport(outcome=_combine(results), per_action=tuple(results))


def _combine(results: list[ActionSubsumptionResult]) -> SubsumptionOutcome:
    if any(r.outcome is SubsumptionOutcome.EXPANSION for r in results):
        return SubsumptionOutcome.EXPANSION
    if any(r.outcome is SubsumptionOutcome.UNPROVEN for r in results):
        return SubsumptionOutcome.UNPROVEN
    return SubsumptionOutcome.NARROWING


def _actions_in_schema(schema: GeneratedSchema) -> list[str]:
    ns_json = schema.schema_json.get(schema.namespace, {})
    actions = ns_json.get("actions", {})
    return list(actions.keys())


def _context_var_types(schema: GeneratedSchema, action: str) -> dict[str, str]:
    """Map each `context.input` attribute of `action` to one of
    `"String"`/`"Long"`/`"Bool"`. An attribute that is optional, or whose
    declared type isn't one of those three, is simply omitted -- which is
    exactly what makes a condition that references it raise
    `UnsupportedConditionError` later (see `_resolve_context_attr`).
    """
    ns_json = schema.schema_json.get(schema.namespace, {})
    common_types = ns_json.get("commonTypes", {})
    input_type = common_types.get(f"{action}Input", {})
    attributes = input_type.get("attributes", {})
    result: dict[str, str] = {}
    for name, info in attributes.items():
        if info.get("required") is False:
            continue
        type_name = info.get("name")
        if type_name in _SUPPORTED_ATTR_TYPES:
            result[name] = type_name
    return result


def _z3_var(name: str, type_name: str) -> z3.ExprRef:
    if type_name == "String":
        return z3.String(name)
    if type_name == "Long":
        return z3.Int(name)
    if type_name == "Bool":
        return z3.Bool(name)
    raise UnsupportedConditionError(
        f"unsupported context attribute type {type_name!r}"
    )  # pragma: no cover


def _check_one_action(
    *,
    action: str,
    old_policies: dict[str, Any],
    new_policies: dict[str, Any],
    schema: GeneratedSchema,
    session_id: str,
    timeout_ms: int,
) -> ActionSubsumptionResult:
    context_vars = {
        name: _z3_var(name, type_name)
        for name, type_name in _context_var_types(schema, action).items()
    }

    try:
        old_formula = _decision_formula(
            old_policies, action=action, session_id=session_id, context_vars=context_vars
        )
        new_formula = _decision_formula(
            new_policies, action=action, session_id=session_id, context_vars=context_vars
        )
    except (
        Exception
    ) as exc:  # fail-closed: ANY translation failure is unproven, never silently narrowing
        return ActionSubsumptionResult(
            action=action,
            outcome=SubsumptionOutcome.UNPROVEN,
            detail=f"could not translate policy conditions: {exc}",
        )

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(z3.And(new_formula, z3.Not(old_formula)))

    try:
        check = solver.check()
    except (
        Exception
    ) as exc:  # pragma: no cover -- defensive: an unexpected z3 failure is unproven, not a crash
        return ActionSubsumptionResult(
            action=action, outcome=SubsumptionOutcome.UNPROVEN, detail=f"z3 solver raised: {exc}"
        )

    if check == z3.unsat:
        return ActionSubsumptionResult(
            action=action,
            outcome=SubsumptionOutcome.NARROWING,
            detail="proved: every context the new policy permits, the old policy already permitted",
        )
    if check == z3.sat:
        model = solver.model()
        witness = ", ".join(f"{decl.name()}={model[decl]}" for decl in model.decls())
        witness = witness or "no context attributes involved"
        return ActionSubsumptionResult(
            action=action,
            outcome=SubsumptionOutcome.EXPANSION,
            detail=f"counterexample: new policy permits a case the old policy denies ({witness})",
        )
    return ActionSubsumptionResult(
        action=action,
        outcome=SubsumptionOutcome.UNPROVEN,
        detail=f"z3 could not decide within {timeout_ms}ms (result: {check})",
    )


def _decision_formula(
    policy_json: dict[str, Any],
    *,
    action: str,
    session_id: str,
    context_vars: dict[str, z3.ExprRef],
) -> z3.BoolRef:
    if policy_json.get("templates") or policy_json.get("templateLinks"):
        raise UnsupportedConditionError(
            "policy templates are not supported by the subsumption checker"
        )

    permit_terms: list[z3.BoolRef] = []
    forbid_terms: list[z3.BoolRef] = []
    for policy in policy_json.get("staticPolicies", {}).values():
        if not _scope_matches(policy, action=action, session_id=session_id):
            continue
        term = _conditions_formula(policy.get("conditions", []), context_vars)
        effect = policy.get("effect")
        if effect == "permit":
            permit_terms.append(term)
        elif effect == "forbid":
            forbid_terms.append(term)
        else:
            raise UnsupportedConditionError(f"unknown policy effect {effect!r}")

    permit = z3.Or(*permit_terms) if permit_terms else z3.BoolVal(False)
    forbid = z3.Or(*forbid_terms) if forbid_terms else z3.BoolVal(False)
    return z3.And(permit, z3.Not(forbid))


def _scope_matches(policy: dict[str, Any], *, action: str, session_id: str) -> bool:
    if not _scope_matches_entity_set(policy.get("action", {}), action):
        return False
    if not _scope_matches_entity_set(policy.get("principal", {}), session_id):
        return False
    # The resource is always `Tool::"<tool_name>"`, and the tool name is
    # always the action name in this project's generated schema (see
    # `agentshield_policy.pdp.PolicyDecisionPoint.authorize`).
    return _scope_matches_entity_set(policy.get("resource", {}), action)


def _scope_matches_entity_set(scope: dict[str, Any], entity_id: str) -> bool:
    op = scope.get("op")
    if op == "All":
        return True
    if op == "==":
        return bool(scope.get("entity", {}).get("id") == entity_id)
    if op == "in":
        return any(e.get("id") == entity_id for e in scope.get("entities", []))
    raise UnsupportedConditionError(f"unsupported scope op {op!r}")


def _conditions_formula(
    conditions: list[dict[str, Any]], context_vars: dict[str, z3.ExprRef]
) -> z3.BoolRef:
    terms: list[z3.BoolRef] = []
    for condition in conditions:
        body = _translate_bool(condition["body"], context_vars)
        kind = condition.get("kind")
        if kind == "when":
            terms.append(body)
        elif kind == "unless":
            terms.append(z3.Not(body))
        else:
            raise UnsupportedConditionError(f"unknown condition kind {kind!r}")
    return z3.And(*terms) if terms else z3.BoolVal(True)


_COMPARISON_OPS: dict[str, Callable[[Any, Any], Any]] = {
    "==": lambda left, right: left == right,
    "!=": lambda left, right: left != right,
    "<": lambda left, right: left < right,
    "<=": lambda left, right: left <= right,
    ">": lambda left, right: left > right,
    ">=": lambda left, right: left >= right,
}


def _translate_bool(expr: dict[str, Any], context_vars: dict[str, z3.ExprRef]) -> z3.BoolRef:
    result = _translate(expr, context_vars)
    if not z3.is_bool(result):
        raise UnsupportedConditionError("expected a boolean-valued expression")
    return result


def _translate(expr: dict[str, Any], context_vars: dict[str, z3.ExprRef]) -> z3.ExprRef:
    if "Value" in expr:
        return _translate_literal(expr["Value"])
    if "Var" in expr or "." in expr:
        return _resolve_context_attr(expr, context_vars)
    if "&&" in expr:
        node = expr["&&"]
        return z3.And(
            _translate_bool(node["left"], context_vars),
            _translate_bool(node["right"], context_vars),
        )
    if "||" in expr:
        node = expr["||"]
        return z3.Or(
            _translate_bool(node["left"], context_vars),
            _translate_bool(node["right"], context_vars),
        )
    if "!" in expr:
        return z3.Not(_translate_bool(expr["!"]["arg"], context_vars))
    for op, fn in _COMPARISON_OPS.items():
        if op in expr:
            node = expr[op]
            return fn(
                _translate(node["left"], context_vars), _translate(node["right"], context_vars)
            )
    if "in" in expr:
        node = expr["in"]
        left = _translate(node["left"], context_vars)
        items = _translate_set(node["right"], context_vars)
        return z3.Or(*[left == item for item in items]) if items else z3.BoolVal(False)
    if "like" in expr:
        node = expr["like"]
        left = _translate(node["left"], context_vars)
        return z3.InRe(left, _translate_pattern(node["pattern"]))
    raise UnsupportedConditionError(f"unsupported expression node: {sorted(expr.keys())!r}")


def _translate_literal(value: Any) -> z3.ExprRef:
    # `bool` must be checked before `int`: `isinstance(True, int)` is True in Python.
    if isinstance(value, bool):
        return z3.BoolVal(value)
    if isinstance(value, int):
        return z3.IntVal(value)
    if isinstance(value, str):
        return z3.StringVal(value)
    raise UnsupportedConditionError(f"unsupported literal type: {type(value)!r}")


def _attr_path(expr: dict[str, Any]) -> list[str] | None:
    if "Var" in expr:
        var = expr["Var"]
        return [var] if isinstance(var, str) else None
    if "." in expr:
        node = expr["."]
        parent = _attr_path(node["left"])
        if parent is None:
            return None
        return [*parent, node["attr"]]
    return None


def _resolve_context_attr(expr: dict[str, Any], context_vars: dict[str, z3.ExprRef]) -> z3.ExprRef:
    path = _attr_path(expr)
    if path is None or len(path) != 3 or path[0] != "context" or path[1] != "input":
        raise UnsupportedConditionError(f"unsupported attribute reference: {path!r}")
    attr_name = path[2]
    if attr_name not in context_vars:
        raise UnsupportedConditionError(
            f"context attribute {attr_name!r} is optional or has an unsupported type"
        )
    return context_vars[attr_name]


def _translate_set(expr: dict[str, Any], context_vars: dict[str, z3.ExprRef]) -> list[z3.ExprRef]:
    if "Set" not in expr:
        raise UnsupportedConditionError(
            "`in` is only supported against a literal set, not an entity hierarchy"
        )
    return [_translate(item, context_vars) for item in expr["Set"]]


def _translate_pattern(pattern: list[Any]) -> z3.ReRef:
    components: list[z3.ReRef] = []
    for elem in pattern:
        if elem == "Wildcard":
            components.append(z3.Full(z3.ReSort(z3.StringSort())))
        elif isinstance(elem, dict) and "Literal" in elem:
            components.append(z3.Re(elem["Literal"]))
        else:
            raise UnsupportedConditionError(f"unsupported `like` pattern element: {elem!r}")
    if not components:
        return z3.Re("")
    if len(components) == 1:
        return components[0]
    return z3.Concat(*components)
