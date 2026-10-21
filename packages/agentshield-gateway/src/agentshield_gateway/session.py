"""Per-session gateway state: pinned tool schemas, granted capabilities,
the session's accumulated information-flow label, and its lethal-trifecta
state.

This is in-process, in-memory state, which is adequate for a single-worker
gateway. A multi-worker or multi-replica deployment needs this backed by a
shared store (Redis, in the same spirit as the revocation epoch store
planned in the `revocation` package) so that two workers handling the same
session agree on what it has already acquired; that is an explicit,
documented scope boundary of this in-memory implementation, not an
oversight.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentshield_core.capabilities import Capability
from agentshield_core.labels import Label
from agentshield_core.trifecta import TrifectaState

from agentshield_gateway.schema_pinning import PinnedToolSet


@dataclass(slots=True)
class GatewaySession:
    session_id: str
    principal: str | None = None
    pinned_tools: PinnedToolSet = field(default_factory=lambda: PinnedToolSet(digests={}))
    capabilities: dict[str, Capability] = field(default_factory=dict)
    current_label: Label = field(default_factory=Label.bottom)
    trifecta: TrifectaState = field(default_factory=TrifectaState)

    def grant_capability(self, capability: Capability) -> None:
        """Replaces any existing capability for that tool. Capabilities are
        never merged or widened here -- `Capability.attenuate` is the only
        sanctioned way to narrow an existing grant; this is for issuing a
        fresh root grant.
        """
        self.capabilities[capability.tool_name] = capability


class SessionStore:
    """An in-memory session registry, keyed by session id."""

    def __init__(self) -> None:
        self._sessions: dict[str, GatewaySession] = {}

    def get(self, session_id: str) -> GatewaySession | None:
        return self._sessions.get(session_id)

    def get_or_create(self, session_id: str) -> GatewaySession:
        session = self._sessions.get(session_id)
        if session is None:
            session = GatewaySession(session_id=session_id)
            self._sessions[session_id] = session
        return session

    def drop(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
