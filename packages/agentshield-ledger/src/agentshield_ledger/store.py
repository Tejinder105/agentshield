"""Async SQLAlchemy persistence for the ledger.

Mirrors `infra/sql/001_audit_grants.sql`: the application connects as a
role with `INSERT, SELECT` only on these tables, `UPDATE`/`DELETE` revoked
at the database level. This module does not attempt to enforce that from
Python -- it is a database grant, not an ORM constraint -- but it never
issues an UPDATE or DELETE against these tables either, so the two layers
of enforcement agree.

Column types are kept backend-generic (`JSON`, `String` for identifiers)
so the same models can be exercised against SQLite in tests without a live
Postgres instance; the production grants SQL targets Postgres specifically
(JSONB, gen'd UUIDs) for the real deployment.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AuditEntryRow(Base):
    __tablename__ = "audit_entry"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String, index=True)
    event_type: Mapped[str] = mapped_column(String)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String)
    entry_hash: Mapped[str] = mapped_column(String, unique=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class MerkleBatchRow(Base):
    __tablename__ = "merkle_batch"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    start_seq: Mapped[int] = mapped_column(Integer)
    end_seq: Mapped[int] = mapped_column(Integer)
    merkle_root: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    checkpoints: Mapped[list[CheckpointRow]] = relationship(back_populates="batch")


class CheckpointRow(Base):
    __tablename__ = "checkpoint"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    batch_id: Mapped[str] = mapped_column(ForeignKey("merkle_batch.id"))
    signature: Mapped[str] = mapped_column(String)
    prev_checkpoint_hash: Mapped[str] = mapped_column(String)
    anchor_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    batch: Mapped[MerkleBatchRow] = relationship(back_populates="checkpoints")


class AuditTombstoneRow(Base):
    """Per the threat model: retention pruning is never a DELETE. If an
    entry is ever pruned for storage reasons, a tombstone recording its
    hash is written instead, so the ledger can still prove something was
    once there -- and prove exactly what was removed and by whom -- even
    though the full payload is gone.
    """

    __tablename__ = "audit_tombstone"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    pruned_entry_hash: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    pruned_by: Mapped[str] = mapped_column(String)
    pruned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class LedgerRepository:
    """INSERT/SELECT-only data access for the ledger tables.

    Every method here either appends a new row or reads existing rows.
    There is deliberately no `update_entry` or `delete_entry` method: that
    is not an oversight to fill in later, it is the point.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append_entry(
        self,
        *,
        session_id: str,
        event_type: str,
        payload: dict[str, Any],
        prev_hash: str,
        entry_hash: str,
    ) -> AuditEntryRow:
        row = AuditEntryRow(
            session_id=session_id,
            event_type=event_type,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def record_batch(
        self, *, start_seq: int, end_seq: int, merkle_root: str
    ) -> MerkleBatchRow:
        row = MerkleBatchRow(start_seq=start_seq, end_seq=end_seq, merkle_root=merkle_root)
        self._session.add(row)
        await self._session.flush()
        return row

    async def record_checkpoint(
        self,
        *,
        batch_id: str,
        signature: str,
        prev_checkpoint_hash: str,
        anchor_ref: str | None = None,
    ) -> CheckpointRow:
        row = CheckpointRow(
            batch_id=batch_id,
            signature=signature,
            prev_checkpoint_hash=prev_checkpoint_hash,
            anchor_ref=anchor_ref,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def record_tombstone(
        self, *, pruned_entry_hash: str, reason: str, pruned_by: str
    ) -> AuditTombstoneRow:
        row = AuditTombstoneRow(
            pruned_entry_hash=pruned_entry_hash, reason=reason, pruned_by=pruned_by
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def fetch_entries(self, *, session_id: str | None = None) -> list[AuditEntryRow]:
        stmt = select(AuditEntryRow).order_by(AuditEntryRow.seq)
        if session_id is not None:
            stmt = stmt.where(AuditEntryRow.session_id == session_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def export_all(self) -> dict[str, Any]:
        """Produce the same shape `Ledger.export()` does, by reading every
        row back from storage -- used to feed `verify.cli` from a live
        deployment rather than from the in-process `Ledger` object.
        """
        entries = await self.fetch_entries()
        checkpoints_result = await self._session.execute(
            select(CheckpointRow, MerkleBatchRow)
            .join(MerkleBatchRow, CheckpointRow.batch_id == MerkleBatchRow.id)
            .order_by(MerkleBatchRow.end_seq)
        )
        checkpoints = [
            {
                "merkle_root": batch.merkle_root,
                "tree_size": batch.end_seq + 1,
                "prev_checkpoint_hash": cp.prev_checkpoint_hash,
                "timestamp": int(cp.signed_at.timestamp()),
                "signature": cp.signature,
            }
            for cp, batch in checkpoints_result.all()
        ]
        return {
            "entries": [
                {
                    "seq": e.seq,
                    "entry": {"event_type": e.event_type, "payload": e.payload},
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                }
                for e in entries
            ],
            "checkpoints": checkpoints,
        }
