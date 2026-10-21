from agentshield_ledger.checkpoint import (
    GENESIS_CHECKPOINT_HASH,
    checkpoint_hash,
    sign_checkpoint,
    verify_checkpoint,
)
from agentshield_ledger.verify.ed25519_pure import verify as pure_verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_sign_and_verify_round_trip() -> None:
    key = Ed25519PrivateKey.generate()
    cp = sign_checkpoint(
        key,
        merkle_root=b"\x01" * 32,
        tree_size=5,
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
        timestamp=1_700_000_000,
    )
    assert verify_checkpoint(key.public_key(), cp)


def test_tampered_merkle_root_fails_verification() -> None:
    key = Ed25519PrivateKey.generate()
    cp = sign_checkpoint(
        key,
        merkle_root=b"\x01" * 32,
        tree_size=5,
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
        timestamp=1_700_000_000,
    )
    tampered = type(cp)(
        merkle_root_hex="ff" * 32,
        tree_size=cp.tree_size,
        prev_checkpoint_hash=cp.prev_checkpoint_hash,
        timestamp=cp.timestamp,
        signature_hex=cp.signature_hex,
    )
    assert not verify_checkpoint(key.public_key(), tampered)


def test_cross_validates_with_pure_python_verifier() -> None:
    key = Ed25519PrivateKey.generate()
    cp = sign_checkpoint(
        key,
        merkle_root=b"\x02" * 32,
        tree_size=1,
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
        timestamp=1_700_000_001,
    )
    public_key_raw = key.public_key().public_bytes_raw()
    assert pure_verify(public_key_raw, cp.signed_payload(), bytes.fromhex(cp.signature_hex))


def test_checkpoint_hash_changes_if_signature_changes() -> None:
    key = Ed25519PrivateKey.generate()
    cp1 = sign_checkpoint(
        key,
        merkle_root=b"\x03" * 32,
        tree_size=2,
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
        timestamp=1,
    )
    cp2 = sign_checkpoint(
        key,
        merkle_root=b"\x03" * 32,
        tree_size=2,
        prev_checkpoint_hash=GENESIS_CHECKPOINT_HASH,
        timestamp=2,
    )
    assert checkpoint_hash(cp1) != checkpoint_hash(cp2)
