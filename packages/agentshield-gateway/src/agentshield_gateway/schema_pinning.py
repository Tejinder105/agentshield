"""Tool-schema pinning and rug-pull detection.

A session pins the digest of every tool's advertised schema and
description the first time it sees the MCP server's `tools/list`. On every
subsequent call, the gateway re-digests whatever the server *currently*
advertises for that tool and compares it against the pin. A mismatch means
the server changed a tool's behavior contract mid-session without the
session's informed consent -- a supply-chain attack on the agent, not a
benign update -- and the decision pipeline treats it as a hard denial
(step 3 of 8; see `agentshield_gateway.pipeline`).

Deliberately independent of `agentshield_policy.mcp_schema.digest_tools`:
that function digests an entire tool list as one unit (useful for "has
anything at all changed since Cedar schema generation"), whereas rug-pull
detection needs a *per-tool* digest so a single changed tool can be named in
the denial reason rather than invalidating the whole session.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def digest_tool(tool: dict[str, Any]) -> str:
    """A stable digest of one tool's `tools/list` entry (name, description,
    input schema, annotations -- whatever the server sent).

    Uses plain `sort_keys` JSON rather than the float-rejecting canonical
    encoder in `agentshield_ledger.verify.canonical`: JSON Schema entries
    legitimately contain floats (e.g. `"minimum": 0.5`), and rejecting them
    here would make pinning unusable for a large fraction of real tool
    schemas. Rug-pull detection only needs byte-stable hashing, not the
    ledger's stronger "every value round-trips unambiguously" guarantee.
    """
    payload = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PinnedToolSet:
    """The digests pinned for a session at the moment it first observed
    `tools/list`. Immutable: re-pinning means starting a new session, not
    mutating this one -- a session that could silently re-pin after a
    rug-pull would defeat the point of pinning.
    """

    digests: dict[str, str]

    @staticmethod
    def pin(tools: list[dict[str, Any]]) -> PinnedToolSet:
        by_name: dict[str, str] = {}
        for tool in tools:
            name = tool.get("name")
            if isinstance(name, str):
                by_name[name] = digest_tool(tool)
        return PinnedToolSet(digests=by_name)

    def check(self, tool_name: str, current_tool: dict[str, Any] | None) -> bool:
        """True iff `current_tool`'s digest matches what was pinned for
        `tool_name`.

        Returns False -- treat it exactly like a detected rug pull -- both
        when the tool was never pinned at session start, and when the
        caller cannot supply the tool's current advertised schema at all.
        An unverifiable schema is as dangerous as a changed one; this
        function does not distinguish "definitely tampered" from "cannot
        prove it wasn't," by design (fail-closed).
        """
        pinned = self.digests.get(tool_name)
        if pinned is None or current_tool is None:
            return False
        return digest_tool(current_tool) == pinned
