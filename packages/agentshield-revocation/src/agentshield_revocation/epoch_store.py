"""Global and per-session revocation epoch counters.

A `Capability` (see `agentshield_core.capabilities`) is minted with a
snapshot of "the current epoch" baked in (`Capability.epoch`), and the
gateway's decision pipeline (step 2) denies any call whose capability's
epoch does not exactly match what `EpochStore.current_epoch` returns right
now. Bumping *either* counter therefore invalidates every capability
minted before the bump, without the store ever needing to enumerate or
touch a single capability directly -- that is what gives revocation its
*bounded latency*: the next call on every affected session is denied the
moment the bump itself completes, not when some sweep eventually gets
around to it (see docs/threat-model.md's "revocation-bounded-latency" and
"capability TTLs" invariants: a capability that somehow dodges this check
entirely still self-expires shortly, from its own short TTL).

A session's effective epoch is `max(global_epoch, session_epoch[session])`:
bumping the global counter invalidates *every* session's capabilities at
once (the kill switch); bumping one session's counter invalidates only
that session's, without disturbing anyone else -- both are monotonically
increasing, so there is no way to "un-bump" your way back to validity.
"""

from __future__ import annotations

from typing import Any, Protocol

_GLOBAL_KEY = "__global__"


class EpochStore(Protocol):
    async def current_epoch(self, session_id: str) -> int:
        """`max(global_epoch, session_epoch[session_id])`. This exact
        signature is what satisfies `agentshield_gateway.boundaries.
        EpochSource`'s structural Protocol -- this package does not import
        or depend on `agentshield-gateway`.
        """
        ...

    async def bump_global_epoch(self) -> int:
        """Invalidate every capability in every session. Returns the new
        global epoch.
        """
        ...

    async def bump_session_epoch(self, session_id: str) -> int:
        """Invalidate every capability in exactly `session_id`. Returns
        the new effective epoch for that session.
        """
        ...


class InMemoryEpochStore:
    """A single-process epoch store, for tests and a single-worker
    gateway. See `RedisEpochStore` for a shared, multi-worker-safe one.
    """

    def __init__(self) -> None:
        self._global_epoch = 0
        self._session_epochs: dict[str, int] = {}

    async def current_epoch(self, session_id: str) -> int:
        return max(self._global_epoch, self._session_epochs.get(session_id, 0))

    async def bump_global_epoch(self) -> int:
        self._global_epoch += 1
        return self._global_epoch

    async def bump_session_epoch(self, session_id: str) -> int:
        new_value = self._session_epochs.get(session_id, 0) + 1
        self._session_epochs[session_id] = new_value
        return max(self._global_epoch, new_value)


class RedisEpochStore:
    """Backed by `INCR`, which is itself atomic -- concurrent kill-switch
    triggers (unlikely, but an incident is exactly the moment unlikely
    things happen) still produce a strictly increasing sequence of epochs
    rather than a lost update.
    """

    def __init__(self, redis_client: Any, *, key_prefix: str = "agentshield:epoch:") -> None:
        self._redis = redis_client
        self._prefix = key_prefix

    def _global_key(self) -> str:
        return f"{self._prefix}{_GLOBAL_KEY}"

    def _session_key(self, session_id: str) -> str:
        return f"{self._prefix}session:{session_id}"

    async def current_epoch(self, session_id: str) -> int:
        global_raw = await self._redis.get(self._global_key())
        session_raw = await self._redis.get(self._session_key(session_id))
        return max(_as_int(global_raw), _as_int(session_raw))

    async def bump_global_epoch(self) -> int:
        new_value = await self._redis.incr(self._global_key())
        return int(new_value)

    async def bump_session_epoch(self, session_id: str) -> int:
        session_value = await self._redis.incr(self._session_key(session_id))
        global_value = _as_int(await self._redis.get(self._global_key()))
        return max(global_value, int(session_value))


def _as_int(raw: Any) -> int:
    if raw is None:
        return 0
    if isinstance(raw, bytes):
        return int(raw.decode("utf-8"))
    return int(raw)
