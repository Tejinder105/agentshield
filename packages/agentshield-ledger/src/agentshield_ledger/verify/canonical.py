"""A restricted, dependency-free JSON canonicalization, modeled on RFC 8785
(the JSON Canonicalization Scheme, JCS).

Full RFC 8785 compliance requires exactly reproducing ECMAScript's
`Number::toString` for floating-point values, which is intricate enough
that getting it subtly wrong is worse than refusing floats outright.
Ledger entries never need them: timestamps are integer epoch values and
amounts are integer minor units. This canonicalizer therefore rejects any
float rather than risk a silent, unauditable serialization mismatch.

For everything it does accept -- object key ordering, string escaping,
separators, UTF-8 encoding -- this produces output byte-identical to RFC
8785.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when a value cannot be safely canonicalized (e.g. a float)."""


def _reject_floats(obj: Any) -> Any:
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        raise CanonicalizationError(
            "ledger entries must not contain floats; use integers (e.g. epoch "
            "nanoseconds, minor currency units) so canonicalization is unambiguous"
        )
    if isinstance(obj, dict):
        return {k: _reject_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_reject_floats(v) for v in obj]
    return obj


def canonicalize(obj: Any) -> bytes:
    """Serialize `obj` to canonical JSON bytes: sorted keys, no
    insignificant whitespace, UTF-8, floats rejected.
    """
    checked = _reject_floats(obj)
    text = json.dumps(checked, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")
