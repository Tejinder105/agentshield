from __future__ import annotations

import pytest
from agentshield_ledger.ledger import Ledger
from agentshield_revocation.blast_radius import build_blast_radius_report
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _ledger() -> Ledger:
    return Ledger(signing_key=Ed25519PrivateKey.generate())


def test_window_must_not_be_inverted() -> None:
    with pytest.raises(ValueError, match="window_end"):
        build_blast_radius_report([], window_start=100, window_end=50)


def test_empty_ledger_is_an_empty_report() -> None:
    report = build_blast_radius_report([], window_start=0, window_end=10_000_000_000)
    assert report.is_empty
    assert report.count == 0
    assert report.affected_sessions == frozenset()


def test_only_tool_outcome_entries_with_a_completed_status_are_counted() -> None:
    ledger = _ledger()
    ledger.append("decision", {"session_id": "s1", "tool": "send_email", "status": "n/a"})
    ledger.append(
        "tool_outcome", {"session_id": "s1", "tool": "send_email", "status": "ok", "result": {}}
    )
    ledger.append(
        "tool_outcome",
        {"session_id": "s1", "tool": "transfer_funds", "status": "uncertain", "error": "timeout"},
    )
    # A clean denial got through zero damage -- it must not show up as "blast radius".
    ledger.append("decision", {"session_id": "s1", "tool": "delete_db", "status": "denied"})

    report = build_blast_radius_report(ledger.entries, window_start=0, window_end=10_000_000_000)

    assert report.count == 2
    statuses = {e.status for e in report.entries}
    assert statuses == {"ok", "uncertain"}
    tool_names = {e.tool_name for e in report.entries}
    assert tool_names == {"send_email", "transfer_funds"}


def test_window_excludes_entries_outside_the_timestamp_range() -> None:
    ledger = _ledger()
    ledger.append("tool_outcome", {"session_id": "s1", "tool": "t", "status": "ok"})
    exported = ledger.export()["entries"]
    real_ts = exported[0]["entry"]["ts"]

    too_early = build_blast_radius_report(
        exported, window_start=real_ts + 1, window_end=real_ts + 100
    )
    assert too_early.is_empty

    too_late = build_blast_radius_report(
        exported, window_start=real_ts - 100, window_end=real_ts - 1
    )
    assert too_late.is_empty

    inside = build_blast_radius_report(exported, window_start=real_ts, window_end=real_ts)
    assert inside.count == 1


def test_accepts_the_export_dict_shape_as_well_as_raw_entries() -> None:
    ledger = _ledger()
    ledger.append("tool_outcome", {"session_id": "s1", "tool": "t", "status": "ok"})
    ledger.append("tool_outcome", {"session_id": "s2", "tool": "t2", "status": "uncertain"})

    from_entries = build_blast_radius_report(
        ledger.entries, window_start=0, window_end=10_000_000_000
    )
    from_export = build_blast_radius_report(
        ledger.export()["entries"], window_start=0, window_end=10_000_000_000
    )

    assert from_entries.count == from_export.count == 2
    assert {e.entry_hash for e in from_entries.entries} == {
        e.entry_hash for e in from_export.entries
    }


def test_affected_sessions_deduplicates() -> None:
    ledger = _ledger()
    ledger.append("tool_outcome", {"session_id": "s1", "tool": "t1", "status": "ok"})
    ledger.append("tool_outcome", {"session_id": "s1", "tool": "t2", "status": "ok"})
    ledger.append("tool_outcome", {"session_id": "s2", "tool": "t3", "status": "uncertain"})

    report = build_blast_radius_report(ledger.entries, window_start=0, window_end=10_000_000_000)

    assert report.affected_sessions == frozenset({"s1", "s2"})


def test_custom_event_type_can_be_selected() -> None:
    ledger = _ledger()
    ledger.append("kill_switch_triggered", {"status": "ok", "session_id": None})

    report = build_blast_radius_report(
        ledger.entries,
        window_start=0,
        window_end=10_000_000_000,
        event_type="kill_switch_triggered",
    )
    assert report.count == 1

    default_event_type = build_blast_radius_report(
        ledger.entries, window_start=0, window_end=10_000_000_000
    )
    assert default_event_type.is_empty  # wrong event_type ("tool_outcome") for this entry
