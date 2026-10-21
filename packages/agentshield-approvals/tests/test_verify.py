from __future__ import annotations

from agentshield_approvals.receipt import Receipt, sign_receipt
from agentshield_approvals.verify import verify_receipt_offline
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _signed(
    key: Ed25519PrivateKey | None = None, **overrides: object
) -> tuple[Ed25519PrivateKey, Receipt]:
    key = key or Ed25519PrivateKey.generate()
    defaults: dict[str, object] = {
        "session_id": "s1",
        "tool_name": "send_email",
        "arguments": {"to": "alice@example.com"},
        "resource_version": 1,
        "nonce": "n1",
        "ttl_seconds": 300.0,
    }
    defaults.update(overrides)
    receipt = sign_receipt(key, **defaults)  # type: ignore[arg-type]
    return key, receipt


def test_valid_receipt_verifies() -> None:
    key, receipt = _signed()
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
        resource_version=1,
    )
    assert result.ok


def test_wrong_session_is_rejected() -> None:
    key, receipt = _signed()
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s2",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert not result.ok
    assert "session" in result.reason


def test_wrong_tool_is_rejected() -> None:
    key, receipt = _signed()
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert not result.ok
    assert "tool" in result.reason


def test_different_arguments_are_rejected() -> None:
    key, receipt = _signed()
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "mallory@example.com"},
        now=0,
    )
    assert not result.ok
    assert "arguments" in result.reason


def test_stale_resource_version_is_rejected() -> None:
    key, receipt = _signed(resource_version=5)
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
        resource_version=6,  # the resource moved on after approval
    )
    assert not result.ok
    assert "resource" in result.reason


def test_resource_version_check_is_skipped_when_not_supplied() -> None:
    key, receipt = _signed(resource_version=5)
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
        resource_version=None,
    )
    assert result.ok


def test_expired_receipt_is_rejected() -> None:
    key, receipt = _signed(ttl_seconds=1.0)
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=receipt.payload.exp + 1000,
    )
    assert not result.ok
    assert "expired" in result.reason


def test_tampered_signature_is_rejected() -> None:
    key, receipt = _signed()
    tampered = type(receipt)(payload=receipt.payload, signature_hex="00" * 64)
    result = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        tampered,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert not result.ok
    assert "signature" in result.reason


def test_wrong_public_key_is_rejected() -> None:
    key, receipt = _signed()
    other_key = Ed25519PrivateKey.generate()
    result = verify_receipt_offline(
        other_key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert not result.ok


def test_malformed_public_key_hex_does_not_raise() -> None:
    _key, receipt = _signed()
    result = verify_receipt_offline(
        "not-valid-hex!!",
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert not result.ok


def test_verification_result_is_truthy_only_when_ok() -> None:
    key, receipt = _signed()
    good = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    bad = verify_receipt_offline(
        key.public_key().public_bytes_raw().hex(),
        receipt,
        session_id="wrong",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        now=0,
    )
    assert bool(good) is True
    assert bool(bad) is False
