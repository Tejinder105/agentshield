"""A minimal, pure-Python, stdlib-only Ed25519 *verifier*.

Deliberately verification-only -- no signing, no key generation -- and
deliberately dependency-free: it exists so an external auditor can check
an Agent Shield ledger checkpoint's signature without installing anything
beyond a standard Python interpreter, and without having to trust the
server's own dependency tree (which includes the much larger
`cryptography` package the server actually uses for signing, in
`agentshield_ledger.checkpoint`).

This is a direct, unoptimized implementation of RFC 8032's Ed25519
verification algorithm over the twisted Edwards curve
`-x^2 + y^2 = 1 + d*x^2*y^2 (mod p)`, `p = 2^255 - 19`. It is correct but
not constant-time; that is an acceptable trade-off for an offline,
read-only verification tool that never handles secret key material.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_Q = 2**252 + 27742317777372353535851937790883648493  # Ed25519 group order L
_BASE_Y = 4 * pow(5, _P - 2, _P) % _P  # standard Ed25519 generator's y-coordinate

Point = tuple[int, int]


def _recover_x(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x % 2 != sign:
        x = _P - x
    return x


def _point_add(p: Point, q: Point) -> Point:
    x1, y1 = p
    x2, y2 = q
    dxy = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxy, _P - 2, _P) % _P
    return x3 % _P, y3 % _P


def _scalar_mult(point: Point, scalar: int) -> Point:
    result: Point = (0, 1)  # identity element of the curve group
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _base_point() -> Point:
    y = _BASE_Y
    return _recover_x(y, 0), y


def _encode_point(point: Point) -> bytes:
    x, y = point
    out = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        out[31] |= 0x80
    return bytes(out)


def _decode_point(data: bytes) -> Point | None:
    if len(data) != 32:
        return None
    sign = (data[31] >> 7) & 1
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    point = (x, y)
    if _encode_point(point) != data:
        return None
    return point


def _sha512_int(*chunks: bytes) -> int:
    h = hashlib.sha512()
    for chunk in chunks:
        h.update(chunk)
    return int.from_bytes(h.digest(), "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature over `message`.

    Returns False for any malformed or invalid input rather than raising,
    so a caller (notably `verify.cli`) can treat "signature invalid" and
    "signature malformed" identically: both mean the ledger is not
    trustworthy as presented.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point = _decode_point(public_key)
    if a_point is None:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    r_point = _decode_point(r_bytes)
    if r_point is None:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= _Q:
        return False

    k = _sha512_int(r_bytes, public_key, message) % _Q
    base = _base_point()
    left = _scalar_mult(base, s)
    right = _point_add(r_point, _scalar_mult(a_point, k))
    return _encode_point(left) == _encode_point(right)
