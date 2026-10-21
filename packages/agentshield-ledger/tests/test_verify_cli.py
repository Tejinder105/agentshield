from __future__ import annotations

import json
from pathlib import Path

import pytest
from agentshield_ledger.ledger import Ledger
from agentshield_ledger.verify.cli import main
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _write_export(tmp_path: Path, key: Ed25519PrivateKey) -> Path:
    ledger = Ledger(signing_key=key)
    for i in range(10):
        ledger.append("event", {"i": i})
        if i % 4 == 0:
            ledger.checkpoint_now()
    ledger.checkpoint_now()
    path = tmp_path / "export.json"
    path.write_text(json.dumps(ledger.export()), encoding="utf-8")
    return path


def test_cli_reports_ok_for_a_valid_export(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = Ed25519PrivateKey.generate()
    export_path = _write_export(tmp_path, key)
    public_key_hex = key.public_key().public_bytes_raw().hex()

    exit_code = main([str(export_path), "--public-key", public_key_hex])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert out.startswith("OK:")


def test_cli_detects_tampering(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = Ed25519PrivateKey.generate()
    export_path = _write_export(tmp_path, key)
    export = json.loads(export_path.read_text(encoding="utf-8"))
    export["entries"][3]["entry"]["payload"]["i"] = 9999
    export_path.write_text(json.dumps(export), encoding="utf-8")
    public_key_hex = key.public_key().public_bytes_raw().hex()

    exit_code = main([str(export_path), "--public-key", public_key_hex])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "TAMPER DETECTED" in err


def test_cli_detects_wrong_public_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = Ed25519PrivateKey.generate()
    export_path = _write_export(tmp_path, key)
    wrong_key = Ed25519PrivateKey.generate()
    wrong_public_hex = wrong_key.public_key().public_bytes_raw().hex()

    exit_code = main([str(export_path), "--public-key", wrong_public_hex])

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "TAMPER DETECTED" in err


def test_cli_reports_malformed_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    export_path = tmp_path / "bad.json"
    export_path.write_text(json.dumps({"entries": []}), encoding="utf-8")  # missing checkpoints

    exit_code = main([str(export_path), "--public-key", "00" * 32])

    assert exit_code == 2
    err = capsys.readouterr().err
    assert "MALFORMED EXPORT" in err
