"""Single-use nonce enforcement.

A receipt's signature alone only proves "a human approved this once"; it
says nothing about *how many times* it has been redeemed. `NonceStore`
turns the receipt's `nonce` field into an actual single-use token by
atomically claiming it the first (and only the first) time it is
presented.
"""

from __future__ import annotations

import time
from typing import Any, Protocol


class NonceStore(Protocol):
    async def claim(self, nonce: str, *, ttl_seconds: float) -> bool:
        """Atomically mark `nonce` as used.

        Returns True iff this call is the first to successfully claim it
        (the caller may proceed); False if it was already claimed -- a
        replay. `ttl_seconds` bounds how long the store needs to remember
        the nonce at all: once a receipt's own `exp` has passed, nothing
        can ever present it again validly (see
        `agentshield_approvals.verify`), so the store does not need to
        remember claimed nonces forever.
        """
        ...


class InMemoryNonceStore:
    """A single-process nonce store, for tests and for a single-worker
    gateway. A multi-worker deployment needs `RedisNonceStore` (or an
    equivalent shared store) so that two workers presented with the same
    replayed receipt agree on which one claimed it first.
    """

    def __init__(self) -> None:
        self._claimed_until: dict[str, float] = {}

    async def claim(self, nonce: str, *, ttl_seconds: float) -> bool:
        now = time.time()
        expiry = self._claimed_until.get(nonce)
        if expiry is not None and expiry > now:
            return False
        self._claimed_until[nonce] = now + ttl_seconds
        return True


class RedisNonceStore:
    """Backed by a single atomic `SET key value NX EX ttl`: "set this key
    only if it does not already exist, and expire it automatically" is
    precisely the claim-once-with-a-bound-lifetime primitive single-use
    enforcement needs, in one round trip with no separate check-then-set
    race window.
    """

    def __init__(self, redis_client: Any, *, key_prefix: str = "agentshield:nonce:") -> None:
        self._redis = redis_client
        self._prefix = key_prefix

    async def claim(self, nonce: str, *, ttl_seconds: float) -> bool:
        key = f"{self._prefix}{nonce}"
        result = await self._redis.set(key, "1", nx=True, ex=max(1, int(ttl_seconds)))
        return bool(result)
