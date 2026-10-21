"""Blast-radius reporting: what, if anything, got through during the
exposure window.

Revocation has *bounded* latency, not *zero* latency (see
docs/threat-model.md): a call already past the gateway pipeline's step 7
(receipt check) when the kill switch fires can still reach step 8
(dispatch) and complete, landing in the ledger as a `tool_outcome` entry
with status `"ok"` or `"uncertain"`. This module answers the incident
question "what completed, and when?" by reading *only* the tamper-evident
ledger -- never live, mutable, in-memory session state -- over a
caller-supplied window (typically: suspected-compromise-start through
kill-switch-triggered_at).

It accepts either `Ledger.entries` (a list of `ChainedEntry`) or the
`"entries"` list from `Ledger.export()` (plain dicts); both expose the
same `event_type` / `payload` / `ts` shape, so this module only ever
depends on `agentshield-ledger` for a type hint, never for behavior.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agentshield_ledger.verify.hashchain import ChainedEntry

_COMPLETED_STATUSES = frozenset({"ok", "uncertain"})

_RawEntry = ChainedEntry | dict[str, Any]


@dataclass(frozen=True, slots=True)
class BlastRadiusEntry:
    seq: int
    entry_hash: str
    session_id: str | None
    tool_name: str | None
    status: str | None
    ts: int | None


@dataclass(frozen=True, slots=True)
class BlastRadiusReport:
    window_start: int
    window_end: int
    entries: tuple[BlastRadiusEntry, ...]

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def is_empty(self) -> bool:
        return self.count == 0

    @property
    def affected_sessions(self) -> frozenset[str]:
        return frozenset(e.session_id for e in self.entries if e.session_id is not None)


def build_blast_radius_report(
    entries: Sequence[_RawEntry],
    *,
    window_start: int,
    window_end: int,
    event_type: str = "tool_outcome",
) -> BlastRadiusReport:
    """Entries whose `event_type` matches (default: `"tool_outcome"`),
    whose integer `ts` falls in `[window_start, window_end]` inclusive,
    and whose `payload["status"]` is one that means the call actually
    completed (`"ok"` or `"uncertain"` -- a cleanly `"denied"` call did
    not get through, by definition, and is deliberately excluded).

    Raises `ValueError` if `window_end` precedes `window_start` -- an
    inverted window almost certainly means the caller mixed up which
    timestamp is which, and silently returning an empty report on an
    incident-response path would be far worse than failing loudly.
    """
    if window_end < window_start:
        raise ValueError("window_end must not precede window_start")

    found: list[BlastRadiusEntry] = []
    for raw in entries:
        seq, entry = _unwrap(raw)
        if entry.get("event_type") != event_type:
            continue
        ts = entry.get("ts")
        if not isinstance(ts, int) or not (window_start <= ts <= window_end):
            continue
        payload = entry.get("payload") or {}
        status = payload.get("status")
        if status not in _COMPLETED_STATUSES:
            continue
        found.append(
            BlastRadiusEntry(
                seq=seq,
                entry_hash=_entry_hash(raw),
                session_id=payload.get("session_id"),
                tool_name=payload.get("tool") or payload.get("tool_name"),
                status=status,
                ts=ts,
            )
        )
    return BlastRadiusReport(window_start=window_start, window_end=window_end, entries=tuple(found))


def _unwrap(raw: _RawEntry) -> tuple[int, dict[str, Any]]:
    if isinstance(raw, dict):
        return int(raw["seq"]), raw["entry"]
    return raw.seq, raw.entry


def _entry_hash(raw: _RawEntry) -> str:
    if isinstance(raw, dict):
        return str(raw["entry_hash"])
    return raw.entry_hash
