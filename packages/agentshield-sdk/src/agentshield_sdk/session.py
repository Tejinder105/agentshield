"""Per-session SDK-side state: the var-handle store, the session's
accumulated information-flow label, and its lethal-trifecta state.

This mirrors `agentshield_gateway.session.GatewaySession` deliberately --
both track the same two session invariants (accumulated label, trifecta
legs) -- but `SdkSession` lives *inside* the trusted orchestrator process,
with per-value visibility the gateway cannot have: by the time a call
reaches the gateway, every argument is already flattened into plain JSON,
so the gateway can only reason about the *whole call's* label (via
`ToolCallRequest.input_label`). `SdkSession` is what computes that label
correctly in the first place, from the actual provenance of each
individual value that went into the call -- see `agentshield_sdk.dispatch`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentshield_core.labels import Label
from agentshield_core.provenance import TaintedValue
from agentshield_core.trifecta import TrifectaLeg, TrifectaState

from agentshield_sdk.handles import VarHandle, VarStore


@dataclass(slots=True)
class SdkSession:
    session_id: str
    var_store: VarStore = field(default_factory=VarStore)
    current_label: Label = field(default_factory=Label.bottom)
    trifecta: TrifectaState = field(default_factory=TrifectaState)

    def label_tool_result(self, value: Any, *, source: str, label: Label) -> TaintedValue[Any]:
        """Wrap a raw tool result with its provenance. Does not store or
        observe it by itself -- see `quarantine_result`, which does both,
        for the common case of "this came from an untrusted source and
        the planner must only ever see a handle to it".
        """
        return TaintedValue.from_source(value, source, label)

    def quarantine_result(
        self, value: Any, *, source: str, label: Label | None = None
    ) -> VarHandle:
        """Label `value`, record its taint against the session's running
        label (`observe`), store it behind a fresh `var_` handle, and
        return the handle -- never the value itself. This is the one
        function that actually implements "untrusted results stored
        behind `var_` handles" from the plan.

        `label` defaults to `Label.untrusted()` -- the correct default for
        a tool result, since the whole point of quarantining it is that it
        came from outside the trust boundary.
        """
        tainted = self.label_tool_result(
            value, source=source, label=label if label is not None else Label.untrusted()
        )
        self.observe(tainted)
        return self.var_store.put(tainted)

    def observe(self, tainted: TaintedValue[Any]) -> None:
        """Fold a value's label into the session's running ceiling. Once
        joined in, a label can never be removed from `current_label` for
        the lifetime of the session -- `Label.join` is monotonic by
        construction (see `agentshield_core.labels`), and that monotonicity
        is exactly what makes the accumulated ceiling meaningful.
        """
        self.current_label = self.current_label.join(tainted.label)

    def would_complete_trifecta(self, leg: TrifectaLeg) -> bool:
        return self.trifecta.would_complete_trifecta(leg)

    def acquire_leg(self, leg: TrifectaLeg) -> None:
        """Callers MUST check `would_complete_trifecta` and refuse to
        proceed *before* calling this -- same caveat as
        `TrifectaState.with_leg_acquired` itself: this only tracks state,
        it does not enforce anything on its own.
        """
        self.trifecta = self.trifecta.with_leg_acquired(leg)
