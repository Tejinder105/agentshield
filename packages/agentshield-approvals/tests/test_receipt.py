from __future__ import annotations

from agentshield_approvals.receipt import Receipt, digest_arguments, sign_receipt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_digest_arguments_is_order_independent() -> None:
    assert digest_arguments({"b": 1, "a": 2}) == digest_arguments({"a": 2, "b": 1})


def test_digest_arguments_changes_with_content() -> None:
    assert digest_arguments({"to": "alice"}) != digest_arguments({"to": "bob"})


def test_sign_receipt_binds_all_five_fields() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = sign_receipt(
        key,
        session_id="s1",
        tool_name="send_email",
        arguments={"to": "alice@example.com"},
        resource_version=7,
        nonce="nonce-1",
        ttl_seconds=60.0,
    )
    assert receipt.payload.session_id == "s1"
    assert receipt.payload.tool_name == "send_email"
    assert receipt.payload.arg_digest == digest_arguments({"to": "alice@example.com"})
    assert receipt.payload.resource_version == 7
    assert receipt.payload.nonce == "nonce-1"


def test_receipt_is_not_expired_immediately_after_minting() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = sign_receipt(
        key,
        session_id="s1",
        tool_name="t",
        arguments={},
        resource_version=0,
        nonce="n",
        ttl_seconds=60.0,
    )
    assert not receipt.payload.is_expired()


def test_receipt_expires_after_ttl() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = sign_receipt(
        key,
        session_id="s1",
        tool_name="t",
        arguments={},
        resource_version=0,
        nonce="n",
        ttl_seconds=1.0,
    )
    far_future = receipt.payload.exp + 10
    assert receipt.payload.is_expired(now=far_future)


def test_receipt_round_trips_through_json_shaped_dicts() -> None:
    key = Ed25519PrivateKey.generate()
    receipt = sign_receipt(
        key,
        session_id="s1",
        tool_name="transfer_funds",
        arguments={"amount_usd": 50},
        resource_version=3,
        nonce="n1",
        ttl_seconds=120.0,
    )
    round_tripped = Receipt.from_dict(receipt.to_dict())
    assert round_tripped == receipt


def test_different_argument_order_produces_the_same_receipt_binding() -> None:
    key = Ed25519PrivateKey.generate()
    r1 = sign_receipt(
        key,
        session_id="s1",
        tool_name="t",
        arguments={"a": 1, "b": 2},
        resource_version=0,
        nonce="n",
        ttl_seconds=60.0,
    )
    r2 = sign_receipt(
        key,
        session_id="s1",
        tool_name="t",
        arguments={"b": 2, "a": 1},
        resource_version=0,
        nonce="n2",
        ttl_seconds=60.0,
    )
    assert r1.payload.arg_digest == r2.payload.arg_digest
