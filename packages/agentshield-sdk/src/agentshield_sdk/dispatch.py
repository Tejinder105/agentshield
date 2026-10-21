"""Where the SDK side meets the gateway's decision pipeline.

Unlike `agentshield-approvals`, `agentshield-revocation`, and
`agentshield-policy`, this package *does* import `agentshield-gateway`
directly, by design: the whole point of `agentshield-sdk` is to feed the
*same* `DecisionPipeline` the MCP proxy uses with richer input than the
gateway could ever reconstruct on its own from flattened JSON arguments --
specifically, `ToolCallRequest.input_label`, a field the pipeline already
has (see `agentshield_gateway.pipeline`, step 5) precisely so a caller with
per-value provenance visibility can supply it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentshield_core.labels import Label
from agentshield_gateway.dispatch import ToolDispatcher
from agentshield_gateway.pipeline import DecisionPipeline, GatewayOutcome, ToolCallRequest
from agentshield_gateway.session import GatewaySession

from agentshield_sdk.session import SdkSession


def resolve_and_label(
    session: SdkSession, raw_arguments: dict[str, Any]
) -> tuple[dict[str, Any], Label]:
    """The two things that must happen to a planner's proposed tool-call
    arguments before dispatch, in the order that actually matters:

    1. Compute the combined label of every `var_` handle referenced
       anywhere in `raw_arguments` -- *before* dereferencing, since the
       label information lives on the handle, not on the bare token
       string that replaces it.
    2. Dereference every exact-match `var_` token to its real value.

    Returns `(resolved_arguments, input_label)`: `resolved_arguments` is
    what the real tool (and the gateway's Cedar policy, which must see
    real values like `amount_usd <= 100`, not a `var_7` placeholder) is
    actually called with; `input_label` is what the gateway's pipeline
    step 5 joins against the session's own accumulated label.
    """
    label = session.var_store.label_of(raw_arguments)
    resolved = session.var_store.resolve_in(raw_arguments)
    return resolved, label


@dataclass(slots=True)
class SdkGatewayClient:
    """A thin convenience wrapper so a framework integration does not have
    to re-derive the `resolve_and_label` -> `ToolCallRequest` -> pipeline
    dance by hand every time. Holds no state of its own beyond the
    pipeline and dispatcher references; `SdkSession` and `GatewaySession`
    are passed in per call since a real deployment may juggle many
    concurrent sessions through one shared pipeline.
    """

    pipeline: DecisionPipeline
    dispatcher: ToolDispatcher

    async def call_tool(
        self,
        sdk_session: SdkSession,
        gateway_session: GatewaySession,
        *,
        tool_name: str,
        raw_arguments: dict[str, Any],
        raw_context: dict[str, Any],
        current_tool_schema: dict[str, Any] | None = None,
        receipt: Any | None = None,
    ) -> GatewayOutcome:
        resolved_arguments, input_label = resolve_and_label(sdk_session, raw_arguments)
        request = ToolCallRequest(
            session_id=sdk_session.session_id,
            tool_name=tool_name,
            arguments=resolved_arguments,
            raw_context=raw_context,
            current_tool_schema=current_tool_schema,
            input_label=input_label,
            receipt=receipt,
        )
        return await self.pipeline.evaluate_and_dispatch(request, gateway_session, self.dispatcher)
