"""Symbolic `var_` handles: the mechanism behind the dual-LLM quarantine.

An untrusted tool result is never handed to the privileged planner LLM as
raw bytes. Instead it is stored in a `VarStore` and replaced with a
`VarHandle` whose `token` (`"var_3"`, say) is just a plain string the
planner can see, repeat, and pass back as an argument to another tool call
-- entirely symbolically, with no ability to read what it actually
contains. A non-LLM orchestrator (`VarStore.resolve_in`) is what turns that
token back into the real, still-tainted value, and only at the last
possible moment: immediately before the real tool implementation is
invoked (see `agentshield_sdk.toolwrap.quarantine_tool_output`).

This is the concrete mechanism for the plan's "dual-LLM quarantine with
symbolic dereferencing": the planner never reads the injected
`[SYSTEM OVERRIDE]` text at all, because it never receives the text in the
first place -- only a handle to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agentshield_core.labels import Label
from agentshield_core.provenance import TaintedValue

_TOKEN_RE = re.compile(r"\bvar_(\d+)\b")
_FULL_TOKEN_RE = re.compile(r"^var_(\d+)$")


@dataclass(frozen=True, slots=True)
class VarHandle:
    """A symbolic reference to a value held in a `VarStore`. Equality and
    hashing are by `handle_id` alone, so a handle can be used as a dict key
    or compared for identity without ever touching the value it points to.
    """

    handle_id: str

    @property
    def token(self) -> str:
        """The plain-text form a planner LLM actually sees and can repeat
        verbatim in a tool-call argument, e.g. `"var_3"`.
        """
        return f"var_{self.handle_id}"

    @staticmethod
    def parse_token(token: str) -> VarHandle | None:
        """`None` if `token` is not *exactly* a `var_N` token -- this is a
        strict full-string match, not a substring search; see
        `VarStore.label_of` for the substring-aware label-collection pass
        used before this.
        """
        match = _FULL_TOKEN_RE.match(token)
        if match is None:
            return None
        return VarHandle(handle_id=match.group(1))


class UnknownHandleError(KeyError):
    """Raised when a `var_` token names a handle this store never issued,
    or one that has since been dropped. This is deliberately a hard
    error, not a silent pass-through of the literal token string: a
    planner that fabricates its own `var_N` string (rather than one it
    was actually given) must not be able to smuggle an arbitrary string
    literal into a tool call by *pretending* it is a dereferenced handle.
    """


@dataclass(slots=True)
class VarStore:
    """A session-scoped registry of quarantined values. Handles are never
    reused or recycled within a store's lifetime: `handle_id`s are a
    monotonically increasing counter, so a stale handle from an earlier,
    revoked, or expired context can never silently alias a different,
    newer value.
    """

    _values: dict[str, TaintedValue[Any]] = field(default_factory=dict)
    _next_id: int = 1

    def put(self, value: TaintedValue[Any]) -> VarHandle:
        handle = VarHandle(handle_id=str(self._next_id))
        self._next_id += 1
        self._values[handle.handle_id] = value
        return handle

    def get(self, handle: VarHandle) -> TaintedValue[Any]:
        try:
            return self._values[handle.handle_id]
        except KeyError:
            raise UnknownHandleError(handle.token) from None

    def __len__(self) -> int:
        return len(self._values)

    def resolve_in(self, obj: Any) -> Any:
        """Recursively walk `obj` (through `dict`, `list`, and `tuple`)
        and replace every string that is *exactly* a `var_` token with the
        real value it refers to. Everything else -- including a string
        that merely *contains* a token as a substring -- passes through
        unchanged, since substituting a non-string value into the middle
        of a larger string has no well-defined result.

        Raises `UnknownHandleError` for a token this store never issued,
        rather than passing the bare token string through -- a forged
        `"var_999"` argument must fail loudly, not silently become the
        literal string `"var_999"` as if that were an intentional value.
        """
        if isinstance(obj, dict):
            return {k: self.resolve_in(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.resolve_in(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.resolve_in(v) for v in obj)
        if isinstance(obj, str):
            handle = VarHandle.parse_token(obj)
            if handle is None:
                return obj
            return self.get(handle).value
        return obj

    def label_of(self, obj: Any) -> Label:
        """The join of every handle's label referenced *anywhere* inside
        `obj`, including tokens embedded as a substring of a larger
        string (unlike `resolve_in`, which only substitutes exact
        matches). This is deliberately more permissive than `resolve_in`'s
        matching, because a planner mentioning `"see var_3 for details"`
        in a longer string is still touching that value's taint even
        though the string as a whole cannot be literally substituted.

        Computed over the pre-dereference arguments, before `resolve_in`
        replaces the tokens -- that information would otherwise be lost
        the instant substitution happens.
        """
        label = Label.bottom()
        for token in self._find_tokens(obj):
            if token in self._values:
                label = label.join(self._values[token].label)
        return label

    def _find_tokens(self, obj: Any) -> list[str]:
        if isinstance(obj, dict):
            found: list[str] = []
            for v in obj.values():
                found.extend(self._find_tokens(v))
            return found
        if isinstance(obj, list | tuple):
            found = []
            for v in obj:
                found.extend(self._find_tokens(v))
            return found
        if isinstance(obj, str):
            return [m.group(1) for m in _TOKEN_RE.finditer(obj)]
        return []
