from __future__ import annotations

from agentshield_console_api.replay import replay_session
from agentshield_ledger.ledger import Ledger


def test_replay_reconstructs_the_full_session_timeline_in_order(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"})
    ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
    ledger.append("decision", {"session_id": "s2", "decision": "DENY", "stage": "principal"})

    replay = replay_session(ledger.entries, "s1")
    assert replay.session_id == "s1"
    assert replay.chain_intact is True
    assert [s.event_type for s in replay.steps] == ["decision", "tool_outcome"]


def test_replay_final_decision_is_the_last_decision_entry(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"})
    ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
    ledger.append(
        "decision",
        {"session_id": "s1", "decision": "REQUIRE_APPROVAL", "stage": "approval_tiering"},
    )

    replay = replay_session(ledger.entries, "s1")
    assert replay.final_decision == "REQUIRE_APPROVAL"


def test_replay_final_decision_is_none_when_the_session_has_no_decision_entries(
    ledger: Ledger,
) -> None:
    ledger.append("tool_outcome", {"session_id": "s1", "status": "ok"})
    replay = replay_session(ledger.entries, "s1")
    assert replay.final_decision is None


def test_replay_of_an_unknown_session_is_an_empty_but_chain_intact_replay(ledger: Ledger) -> None:
    ledger.append("decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"})
    replay = replay_session(ledger.entries, "no-such-session")
    assert replay.steps == ()
    assert replay.final_decision is None
    assert replay.chain_intact is True


def test_replay_chain_intact_reflects_the_whole_ledger_not_just_this_session(
    ledger: Ledger,
) -> None:
    ledger.append("decision", {"session_id": "s1", "decision": "ALLOW", "stage": "cedar_policy"})
    ledger.append("decision", {"session_id": "s2", "decision": "ALLOW", "stage": "cedar_policy"})
    entries = list(ledger.entries)
    tampered_s2 = entries[1].entry.copy()
    tampered_s2["payload"] = {"session_id": "s2", "decision": "DENY"}
    entries[1] = type(entries[1])(
        seq=entries[1].seq,
        entry=tampered_s2,
        prev_hash=entries[1].prev_hash,
        entry_hash=entries[1].entry_hash,
    )

    # Tampering with session s2's entry must still show up as a broken
    # chain when replaying session s1 -- tamper-evidence is global.
    replay = replay_session(entries, "s1")
    assert replay.chain_intact is False
