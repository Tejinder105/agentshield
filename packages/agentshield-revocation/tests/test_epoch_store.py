from __future__ import annotations

import pytest
from agentshield_revocation.epoch_store import InMemoryEpochStore, RedisEpochStore
from fakeredis.aioredis import FakeRedis

pytestmark = pytest.mark.asyncio


async def test_starts_at_zero_for_every_session() -> None:
    store = InMemoryEpochStore()
    assert await store.current_epoch("s1") == 0
    assert await store.current_epoch("unseen-session") == 0


async def test_global_bump_affects_every_session() -> None:
    store = InMemoryEpochStore()
    assert await store.bump_global_epoch() == 1
    assert await store.current_epoch("s1") == 1
    assert await store.current_epoch("s2") == 1
    assert await store.current_epoch("never-seen-before") == 1


async def test_session_bump_affects_only_that_session() -> None:
    store = InMemoryEpochStore()
    assert await store.bump_session_epoch("s1") == 1
    assert await store.current_epoch("s1") == 1
    assert await store.current_epoch("s2") == 0


async def test_effective_epoch_is_the_max_of_global_and_session() -> None:
    store = InMemoryEpochStore()
    await store.bump_session_epoch("s1")  # s1 -> 1
    await store.bump_global_epoch()  # global -> 1
    await store.bump_global_epoch()  # global -> 2
    assert await store.current_epoch("s1") == 2  # global now dominates
    assert await store.current_epoch("s2") == 2  # untouched session still sees the global bump


async def test_bumps_are_monotonic_never_decrease() -> None:
    store = InMemoryEpochStore()
    seen = [await store.bump_global_epoch() for _ in range(5)]
    assert seen == sorted(seen)
    assert len(set(seen)) == len(seen)


async def test_redis_store_matches_in_memory_semantics() -> None:
    store = RedisEpochStore(FakeRedis())
    assert await store.current_epoch("s1") == 0

    assert await store.bump_session_epoch("s1") == 1
    assert await store.current_epoch("s1") == 1
    assert await store.current_epoch("s2") == 0

    assert await store.bump_global_epoch() == 1
    assert await store.current_epoch("s2") == 1
    assert await store.current_epoch("s1") == 1  # max(1, 1)

    assert await store.bump_global_epoch() == 2
    assert await store.current_epoch("s1") == 2  # global now dominates s1's own bump


async def test_redis_store_key_prefix_is_configurable() -> None:
    client = FakeRedis()
    store_a = RedisEpochStore(client, key_prefix="tenant-a:")
    store_b = RedisEpochStore(client, key_prefix="tenant-b:")
    await store_a.bump_global_epoch()
    assert await store_a.current_epoch("s1") == 1
    assert await store_b.current_epoch("s1") == 0  # isolated namespace, untouched
