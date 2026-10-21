from agentshield_ledger.anchoring import InMemoryAnchor
from agentshield_ledger.checkpoint import verify_checkpoint
from agentshield_ledger.ledger import Ledger
from agentshield_ledger.verify.cli import VerificationFailure, verify_export
from agentshield_ledger.verify.hashchain import verify_chain
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _ledger(anchor: InMemoryAnchor | None = None) -> tuple[Ledger, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    return Ledger(signing_key=key, anchor=anchor), key


def test_append_builds_a_valid_hash_chain() -> None:
    ledger, _ = _ledger()
    ledger.append("tool_call", {"tool": "send_email"})
    ledger.append("decision", {"result": "allow"})
    ledger.append("tool_result", {"status": "ok"})
    assert verify_chain(ledger.entries)


def test_checkpoint_now_produces_a_verifiable_checkpoint() -> None:
    ledger, key = _ledger()
    ledger.append("a", {"x": 1})
    ledger.append("b", {"x": 2})
    cp = ledger.checkpoint_now()
    assert verify_checkpoint(key.public_key(), cp)
    assert cp.tree_size == 2


def test_checkpoint_publishes_to_anchor_when_configured() -> None:
    anchor = InMemoryAnchor()
    ledger, _ = _ledger(anchor)
    ledger.append("a", {"x": 1})
    cp = ledger.checkpoint_now()
    assert anchor.published == [cp]


def test_second_checkpoint_chains_to_first() -> None:
    ledger, _ = _ledger()
    ledger.append("a", {"x": 1})
    cp1 = ledger.checkpoint_now()
    ledger.append("b", {"x": 2})
    cp2 = ledger.checkpoint_now()
    from agentshield_ledger.checkpoint import checkpoint_hash

    assert cp2.prev_checkpoint_hash == checkpoint_hash(cp1)
    assert cp2.tree_size == 2


def test_full_export_verifies_end_to_end_with_pure_verifier() -> None:
    ledger, key = _ledger()
    for i in range(7):
        ledger.append("event", {"i": i})
        if i % 3 == 0:
            ledger.checkpoint_now()
    ledger.checkpoint_now()

    export = ledger.export()
    public_key_hex = key.public_key().public_bytes_raw().hex()
    verify_export(export, public_key_hex)  # must not raise


def test_tampered_export_entry_is_caught_by_verify_export() -> None:
    ledger, key = _ledger()
    ledger.append("a", {"x": 1})
    ledger.append("b", {"x": 2})
    ledger.checkpoint_now()

    export = ledger.export()
    export["entries"][0]["entry"]["payload"]["x"] = 999

    public_key_hex = key.public_key().public_bytes_raw().hex()
    try:
        verify_export(export, public_key_hex)
    except VerificationFailure:
        pass
    else:
        raise AssertionError("expected VerificationFailure for tampered entry")


def test_tampered_checkpoint_signature_is_caught() -> None:
    ledger, key = _ledger()
    ledger.append("a", {"x": 1})
    ledger.checkpoint_now()

    export = ledger.export()
    export["checkpoints"][0]["signature"] = "00" * 64

    public_key_hex = key.public_key().public_bytes_raw().hex()
    try:
        verify_export(export, public_key_hex)
    except VerificationFailure:
        pass
    else:
        raise AssertionError("expected VerificationFailure for forged checkpoint signature")


def test_wrong_public_key_is_caught() -> None:
    ledger, _ = _ledger()
    ledger.append("a", {"x": 1})
    ledger.checkpoint_now()
    export = ledger.export()

    wrong_key = Ed25519PrivateKey.generate()
    wrong_public_hex = wrong_key.public_key().public_bytes_raw().hex()
    try:
        verify_export(export, wrong_public_hex)
    except VerificationFailure:
        pass
    else:
        raise AssertionError("expected VerificationFailure for wrong public key")
