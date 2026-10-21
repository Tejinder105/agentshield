from __future__ import annotations

from typing import Any

import pytest
from agentshield_revocation.epoch_store import InMemoryEpochStore
from agentshield_revocation.kill_switch import KillSwitch

pytestmark = pytest.mark.asyncio


class _FakeApprovalDrain:
    def __init__(self, pending: list[str]) -> None:
        self._pending = pending
        self.drain_calls = 0

    async def drain_pending(self) -> list[str]:
        self.drain_calls += 1
        drained, self._pending = self._pending, []
        return drained


class _FakeLedger:
    def __init__(self) -> None:
        self.appended: list[tuple[str, dict[str, Any]]] = []

    def append(self, event_type: str, payload: dict[str, Any]) -> None:
        self.appended.append((event_type, payload))


async def test_trigger_global_bumps_epoch_and_drains_approvals() -> None:
    epoch_store = InMemoryEpochStore()
    drain = _FakeApprovalDrain(pending=["req-1", "req-2"])
    switch = KillSwitch(epoch_store=epoch_store, approval_drain=drain)

    result = await switch.trigger_global(reason="suspected prompt injection")

    assert result.scope == "global"
    assert result.new_global_epoch == 1
    assert result.drained_approvals == ("req-1", "req-2")
    assert drain.drain_calls == 1
    assert await epoch_store.current_epoch("any-session-at-all") == 1


async def test_trigger_global_without_an_approval_drain_configured() -> None:
    switch = KillSwitch(epoch_store=InMemoryEpochStore())
    result = await switch.trigger_global(reason="test")
    assert result.drained_approvals == ()


async def test_trigger_global_is_idempotent_in_effect() -> None:
    epoch_store = InMemoryEpochStore()
    switch = KillSwitch(epoch_store=epoch_store, approval_drain=_FakeApprovalDrain(pending=[]))
    first = await switch.trigger_global(reason="r1")
    second = await switch.trigger_global(reason="r2")
    assert first.new_global_epoch is not None
    assert second.new_global_epoch == first.new_global_epoch + 1
    assert second.drained_approvals == ()  # already-empty queue, second time around


async def test_trigger_session_only_affects_that_session() -> None:
    epoch_store = InMemoryEpochStore()
    switch = KillSwitch(epoch_store=epoch_store)

    result = await switch.trigger_session("compromised-session", reason="anomalous tool volume")

    assert result.scope == "session"
    assert result.session_id == "compromised-session"
    assert result.new_session_epoch == 1
    assert result.drained_approvals == ()  # session-scoped triggers never drain the global queue
    assert await epoch_store.current_epoch("compromised-session") == 1
    assert await epoch_store.current_epoch("innocent-session") == 0


async def test_trigger_global_writes_one_ledger_entry() -> None:
    ledger = _FakeLedger()
    switch = KillSwitch(epoch_store=InMemoryEpochStore(), ledger=ledger)

    await switch.trigger_global(reason="incident-42")

    assert len(ledger.appended) == 1
    event_type, payload = ledger.appended[0]
    assert event_type == "kill_switch_triggered"
    assert payload["scope"] == "global"
    assert payload["reason"] == "incident-42"
    assert payload["new_global_epoch"] == 1


async def test_trigger_session_writes_one_ledger_entry() -> None:
    ledger = _FakeLedger()
    switch = KillSwitch(epoch_store=InMemoryEpochStore(), ledger=ledger)

    await switch.trigger_session("s1", reason="scoped-incident")

    assert len(ledger.appended) == 1
    event_type, payload = ledger.appended[0]
    assert event_type == "kill_switch_triggered"
    assert payload["scope"] == "session"
    assert payload["session_id"] == "s1"


async def test_triggered_at_uses_the_injected_clock() -> None:
    switch = KillSwitch(epoch_store=InMemoryEpochStore(), clock=lambda: 1_700_000_000.0)
    result = await switch.trigger_global(reason="deterministic-clock-test")
    assert result.triggered_at == 1_700_000_000
