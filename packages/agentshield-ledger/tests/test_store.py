from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from agentshield_ledger.checkpoint import GENESIS_CHECKPOINT_HASH
from agentshield_ledger.store import Base, LedgerRepository
from agentshield_ledger.verify.canonical import canonicalize
from agentshield_ledger.verify.hashchain import ChainedEntry
from agentshield_ledger.verify.merkle import MerkleTree
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def test_append_entry_round_trips(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    row = await repo.append_entry(
        session_id="s1",
        event_type="tool_call",
        payload={"tool": "send_email"},
        prev_hash="0" * 64,
        entry_hash="a" * 64,
    )
    assert row.seq is not None
    fetched = await repo.fetch_entries()
    assert len(fetched) == 1
    assert fetched[0].entry_hash == "a" * 64


async def test_fetch_entries_filters_by_session(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    await repo.append_entry(
        session_id="s1", event_type="e", payload={}, prev_hash="0" * 64, entry_hash="1" * 64
    )
    await repo.append_entry(
        session_id="s2", event_type="e", payload={}, prev_hash="1" * 64, entry_hash="2" * 64
    )
    only_s1 = await repo.fetch_entries(session_id="s1")
    assert [r.entry_hash for r in only_s1] == ["1" * 64]


async def test_fetch_entries_preserves_sequence_order(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    chain = [ChainedEntry.first({"i": 0})]
    for i in range(1, 5):
        chain.append(chain[-1].extend({"i": i}))
    for c in chain:
        await repo.append_entry(
            session_id="s1",
            event_type="e",
            payload=c.entry,
            prev_hash=c.prev_hash,
            entry_hash=c.entry_hash,
        )
    fetched = await repo.fetch_entries()
    assert [r.payload["i"] for r in fetched] == [0, 1, 2, 3, 4]


async def test_record_batch_and_checkpoint_round_trip(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    await repo.append_entry(
        session_id="s1", event_type="e", payload={"x": 1}, prev_hash="0" * 64, entry_hash="a" * 64
    )
    tree = MerkleTree.build([canonicalize({"event_type": "e", "payload": {"x": 1}})])
    batch = await repo.record_batch(start_seq=0, end_seq=0, merkle_root=tree.root.hex())
    cp = await repo.record_checkpoint(
        batch_id=batch.id,
        signature="deadbeef",
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
    )
    assert cp.batch_id == batch.id


async def test_export_all_matches_ledger_export_shape(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    e0 = ChainedEntry.first({"event_type": "a", "payload": {"x": 1}})
    await repo.append_entry(
        session_id="s1",
        event_type="a",
        payload={"x": 1},
        prev_hash=e0.prev_hash,
        entry_hash=e0.entry_hash,
    )
    tree = MerkleTree.build([canonicalize({"event_type": "a", "payload": {"x": 1}})])
    batch = await repo.record_batch(start_seq=0, end_seq=0, merkle_root=tree.root.hex())
    await repo.record_checkpoint(
        batch_id=batch.id, signature="ab" * 32, prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH
    )

    export = await repo.export_all()
    assert export["entries"][0]["entry_hash"] == e0.entry_hash
    assert export["checkpoints"][0]["merkle_root"] == tree.root.hex()
    assert export["checkpoints"][0]["tree_size"] == 1


async def test_tombstone_is_recorded_not_a_delete(session: AsyncSession) -> None:
    repo = LedgerRepository(session)
    await repo.append_entry(
        session_id="s1", event_type="e", payload={}, prev_hash="0" * 64, entry_hash="a" * 64
    )
    tombstone = await repo.record_tombstone(
        pruned_entry_hash="a" * 64, reason="retention", pruned_by="ops-admin"
    )
    assert tombstone.pruned_entry_hash == "a" * 64
    # the original entry is still readable -- a tombstone records that a
    # prune happened, it does not perform one.
    entries = await repo.fetch_entries()
    assert len(entries) == 1
