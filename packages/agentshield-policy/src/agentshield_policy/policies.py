"""Policy loading, schema validation, and the cached PolicySet handle.

Cedar policies are parsed once, at startup or on an explicit reload, into a
`cedarpy.PolicySet` -- not on every authorization call. Re-parsing per call
would make Cedar's own analysis-time guarantees pointless and add needless
latency to every tool call.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import cedarpy

from agentshield_policy.mcp_schema import GeneratedSchema


class PolicyValidationError(RuntimeError):
    """Raised when a policy set fails to parse or fails schema validation.

    Carries the individual Cedar validation error messages so a caller (the
    console's policy editor, for instance) can show exactly which policy
    and attribute was wrong, e.g. a typo'd argument name that the schema
    would otherwise have let through silently.
    """

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


@dataclass(slots=True)
class PolicyStore:
    """Holds the current, validated, parsed Cedar policy set for one
    session (or one deployment-wide default, depending on how the caller
    scopes it).
    """

    policy_text: str
    schema: GeneratedSchema
    _policy_set: cedarpy.PolicySet = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._policy_set = self._parse_and_validate(self.policy_text)

    def _parse_and_validate(self, policy_text: str) -> cedarpy.PolicySet:
        validation = cedarpy.validate_policies(policy_text, self.schema.schema_json)
        if not validation.validation_passed:
            raise PolicyValidationError(
                "Cedar policy failed schema validation",
                errors=[e.error for e in validation.errors],
            )
        try:
            return cedarpy.PolicySet.from_str(policy_text)
        except PolicyValidationError:
            raise
        except Exception as exc:  # cedarpy's own parse exceptions; normalize to our error type
            raise PolicyValidationError(f"Cedar policy failed to parse: {exc}") from exc

    @property
    def policy_set(self) -> cedarpy.PolicySet:
        """The cached, parsed PolicySet handle. Safe to pass to
        `cedarpy.is_authorized` repeatedly without re-parsing.
        """
        return self._policy_set

    def reload(self, new_policy_text: str) -> None:
        """Atomically replace the active policy set after re-validating it.

        If validation or parsing fails, the previously active policy set is
        left completely untouched -- a bad reload must never leave the PDP
        without a usable policy set, since that would otherwise be an
        availability bug masquerading as a security one.
        """
        new_set = self._parse_and_validate(new_policy_text)
        self.policy_text = new_policy_text
        self._policy_set = new_set
