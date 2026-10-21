from __future__ import annotations

from agentshield_console_api.audit import chain_intact, session_entries
from agentshield_ledger.ledger import Ledger


def test_session_entries_filters_by_session_id(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1", "tool": "send_email", "decision": "ALLOW"})
    ledger.append("decision", {"session_id": "s2", "tool": "send_email", "decision": "DENY"})
    ledger.append("tool_outcome", {"session_id": "s1", "tool": "send_email", "status": "ok"})

    views = session_entries(ledger.entries, "s1")
    assert [v.event_type for v in views] == ["decision", "tool_outcome"]
    assert all(v.payload["session_id"] == "s1" for v in views)


def test_session_entries_preserves_append_order(ledger: Ledger) -> None:
    for i in range(5):
        ledger.append("decision", {"session_id": "s1", "seq_marker": i})
    views = session_entries(ledger.entries, "s1")
    assert [v.payload["seq_marker"] for v in views] == [0, 1, 2, 3, 4]
    assert [v.seq for v in views] == [0, 1, 2, 3, 4]


def test_session_entries_excludes_a_global_kill_switch_event(ledger: Ledger) -> None:
    # A global kill switch's ledger entry carries no `session_id` at all --
    # it affects every session, so it is not any one session's event.
    ledger.append(
        "kill_switch_triggered", {"scope": "global", "reason": "incident", "drained_count": 0}
    )
    assert session_entries(ledger.entries, "s1") == []


def test_chain_intact_is_true_for_an_untampered_ledger(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1"})
    ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
    assert chain_intact(ledger.entries) is True


def test_chain_intact_detects_tampering(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1"})
    ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
    entries = list(ledger.entries)
    tampered = entries[0].entry.copy()
    tampered["payload"] = {"session_id": "s1-tampered"}
    entries[0] = type(entries[0])(
        seq=entries[0].seq,
        entry=tampered,
        prev_hash=entries[0].prev_hash,
        entry_hash=entries[0].entry_hash,  # stale hash: doesn't match the new entry contents
    )
    assert chain_intact(entries) is False


def test_chain_intact_on_an_empty_ledger_is_true(ledger: Ledger) -> None:
    assert chain_intact(ledger.entries) is True
