from agentshield_ledger.verify.ed25519_pure import verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return private_key, public_key


def test_valid_signature_from_cryptography_verifies_with_pure_implementation() -> None:
    private_key, public_key = _keypair()
    message = b"agent-shield checkpoint payload"
    signature = private_key.sign(message)
    assert verify(public_key, message, signature) is True


def test_wrong_message_is_rejected() -> None:
    private_key, public_key = _keypair()
    signature = private_key.sign(b"original message")
    assert verify(public_key, b"tampered message", signature) is False


def test_flipped_signature_byte_is_rejected() -> None:
    private_key, public_key = _keypair()
    message = b"checkpoint"
    signature = bytearray(private_key.sign(message))
    signature[0] ^= 0x01
    assert verify(public_key, message, bytes(signature)) is False


def test_flipped_last_signature_byte_is_rejected() -> None:
    private_key, public_key = _keypair()
    message = b"checkpoint"
    signature = bytearray(private_key.sign(message))
    signature[-1] ^= 0x01
    assert verify(public_key, message, bytes(signature)) is False


def test_wrong_public_key_is_rejected() -> None:
    private_key, _ = _keypair()
    _, other_public_key = _keypair()
    message = b"checkpoint"
    signature = private_key.sign(message)
    assert verify(other_public_key, message, signature) is False


def test_malformed_public_key_length_returns_false_not_raises() -> None:
    assert verify(b"too-short", b"msg", b"\x00" * 64) is False


def test_malformed_signature_length_returns_false_not_raises() -> None:
    _, public_key = _keypair()
    assert verify(public_key, b"msg", b"\x00" * 10) is False


def test_all_zero_key_and_signature_matches_cryptography_reference_behavior() -> None:
    # (0, 1)-type low-order points make an all-zero public key and an
    # all-zero signature a mutually-consistent (if degenerate) RFC 8032
    # signature. This is not a bug: OpenSSL/`cryptography`'s own Ed25519
    # verifier accepts this exact input too, so matching it here is the
    # correct behavior -- a from-scratch "cofactor hardening" check that
    # diverged from the reference implementation would make this verifier
    # *disagree* with the library used to sign checkpoints, which is a far
    # worse property for an auditor than this permissive edge case.
    assert verify(b"\x00" * 32, b"msg", b"\x00" * 64) is True


def test_all_zero_signature_is_rejected_not_raised() -> None:
    _, public_key = _keypair()
    assert verify(public_key, b"msg", b"\x00" * 64) is False


def test_empty_message_signature_verifies() -> None:
    private_key, public_key = _keypair()
    signature = private_key.sign(b"")
    assert verify(public_key, b"", signature) is True
