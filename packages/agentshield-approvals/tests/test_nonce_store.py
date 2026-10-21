from __future__ import annotations

import pytest
from agentshield_approvals.nonce_store import InMemoryNonceStore, RedisNonceStore
from fakeredis.aioredis import FakeRedis

pytestmark = pytest.mark.asyncio


async def test_in_memory_first_claim_succeeds() -> None:
    store = InMemoryNonceStore()
    assert await store.claim("n1", ttl_seconds=60.0) is True


async def test_in_memory_second_claim_of_same_nonce_fails() -> None:
    store = InMemoryNonceStore()
    assert await store.claim("n1", ttl_seconds=60.0) is True
    assert await store.claim("n1", ttl_seconds=60.0) is False


async def test_in_memory_different_nonces_are_independent() -> None:
    store = InMemoryNonceStore()
    assert await store.claim("n1", ttl_seconds=60.0) is True
    assert await store.claim("n2", ttl_seconds=60.0) is True


async def test_in_memory_claim_succeeds_again_after_expiry() -> None:
    store = InMemoryNonceStore()
    assert await store.claim("n1", ttl_seconds=-1.0) is True  # already "expired" on arrival
    assert await store.claim("n1", ttl_seconds=60.0) is True


async def test_redis_first_claim_succeeds() -> None:
    redis = FakeRedis()
    store = RedisNonceStore(redis)
    assert await store.claim("n1", ttl_seconds=60.0) is True


async def test_redis_second_claim_of_same_nonce_fails() -> None:
    redis = FakeRedis()
    store = RedisNonceStore(redis)
    assert await store.claim("n1", ttl_seconds=60.0) is True
    assert await store.claim("n1", ttl_seconds=60.0) is False


async def test_redis_different_nonces_are_independent() -> None:
    redis = FakeRedis()
    store = RedisNonceStore(redis)
    assert await store.claim("n1", ttl_seconds=60.0) is True
    assert await store.claim("n2", ttl_seconds=60.0) is True


async def test_redis_store_uses_a_key_prefix_to_avoid_collisions() -> None:
    redis = FakeRedis()
    store_a = RedisNonceStore(redis, key_prefix="service-a:")
    store_b = RedisNonceStore(redis, key_prefix="service-b:")
    assert await store_a.claim("n1", ttl_seconds=60.0) is True
    # Same literal nonce string, different prefix -- must not collide.
    assert await store_b.claim("n1", ttl_seconds=60.0) is True
